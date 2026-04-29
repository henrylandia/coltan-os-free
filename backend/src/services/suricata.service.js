'use strict'

const { exec } = require('child_process')
const { promisify } = require('util')
const execAsync = promisify(exec)
const fs = require('fs').promises

const SURICATA_CONF = '/usr/local/etc/suricata/suricata.yaml'
const SURICATA_RULES = '/usr/local/etc/suricata/rules'
const EVE_LOG = '/var/log/suricata/eve.json'
const FAST_LOG = '/var/log/suricata/fast.log'
const SETTINGS_FILE = '/usr/local/etc/coltan/suricata.json'

async function ensureDir() {
  await execAsync('mkdir -p /usr/local/etc/coltan')
}

async function getSettings() {
  try {
    const content = await fs.readFile(SETTINGS_FILE, 'utf8')
    return JSON.parse(content)
  } catch(e) {
    return {
      interface: '',
      mode: 'ids',
      enabled: false,
      rules: {
        malware: true,
        botcc: true,
        exploit: true,
        trojan: true,
        scan: true,
        policy: false,
        dos: false,
        web: false
      },
      autoBlock: {
        enabled: false,
        categories: {
          scan: true,
          dos: true,
          malware: true,
          botcc: true,
          exploit: true,
          trojan: true,
          policy: false,
          web: false
        }
      }
    }
  }
}

async function saveSettings(settings) {
  await ensureDir()
  await fs.writeFile(SETTINGS_FILE, JSON.stringify(settings, null, 2))
}

async function getInterfaces() {
  try {
    const data = JSON.parse(await fs.readFile('/usr/local/etc/coltan/interfaces.json', 'utf8'))
    return Object.entries(data).map(([name, val]) => ({ name, role: val.role }))
  } catch(e) { return [] }
}

async function generateConfig(settings) {
  const iface = settings.interface || 're0'

  const ruleFiles = []
  if (settings.rules.malware) ruleFiles.push(`  - ${SURICATA_RULES}/emerging-malware.rules`)
  if (settings.rules.botcc) ruleFiles.push(`  - ${SURICATA_RULES}/botcc.rules`)
  if (settings.rules.exploit) ruleFiles.push(`  - ${SURICATA_RULES}/emerging-exploit.rules`)
  if (settings.rules.trojan) ruleFiles.push(`  - ${SURICATA_RULES}/emerging-trojan.rules`)
  if (settings.rules.scan) ruleFiles.push(`  - ${SURICATA_RULES}/emerging-scan.rules`)
  if (settings.rules.policy) ruleFiles.push(`  - ${SURICATA_RULES}/emerging-policy.rules`)
  if (settings.rules.dos) ruleFiles.push(`  - ${SURICATA_RULES}/emerging-dos.rules`)
  if (settings.rules.web) ruleFiles.push(`  - ${SURICATA_RULES}/emerging-web_server.rules`)
  if (settings.rules.web) ruleFiles.push(`  - ${SURICATA_RULES}/emerging-sql.rules`)
  ruleFiles.push(`  - ${SURICATA_RULES}/emerging-user_agents.rules`)

  const yaml = `%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    HTTP_SERVERS: "$HOME_NET"
    SMTP_SERVERS: "$HOME_NET"
    SQL_SERVERS: "$HOME_NET"
    DNS_SERVERS: "$HOME_NET"
    TELNET_SERVERS: "$HOME_NET"
    EXTERNAL_NET: "!$HOME_NET"
  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    SSH_PORTS: 22
    DNP3_PORTS: 20000

default-log-dir: /var/log/suricata/

stats:
  enabled: yes
  interval: 30

outputs:
  - fast:
      enabled: yes
      filename: fast.log
      append: yes
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            payload-printable: yes
        - dns
        - http:
            extended: yes

af-packet:
  - interface: ${iface}
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes

logging:
  default-log-level: notice
  outputs:
    - file:
        enabled: yes
        level: info
        filename: /var/log/suricata/suricata.log

rule-files:
${ruleFiles.join('\n')}

classification-file: /usr/local/etc/suricata/classification.config
reference-config-file: /usr/local/etc/suricata/reference.config

app-layer:
  protocols:
    tls:
      enabled: yes
    http:
      enabled: yes
    dns:
      udp:
        enabled: yes
        detection-ports:
          dp: 53

suppress:
  - gen_id: 1
    track: by_src
    ip: 192.168.0.0/16
    signature: "ET POLICY"
`
  await fs.writeFile(SURICATA_CONF, yaml)
}

async function getStatus() {
  try {
    const { stdout } = await execAsync('pgrep -x suricata 2>/dev/null || echo ""')
    const running = stdout.trim().length > 0

    let alerts = 0
    try {
      const { stdout: wc } = await execAsync(`grep -c '"event_type":"alert"' ${EVE_LOG} 2>/dev/null || echo 0`)
      alerts = parseInt(wc.trim()) || 0
    } catch(e) {}

    const settings = await getSettings()
    return { running, alerts, mode: settings.mode, interface: settings.interface }
  } catch(e) { return { running: false, alerts: 0 } }
}

async function start(settings) {
  try {
    await saveSettings({ ...settings, enabled: true })
    await generateConfig(settings)

    // Update rc.conf
    await execAsync(`sysrc suricata_interface="${settings.interface}"`)
    await execAsync('sysrc suricata_enable="YES"')

    // Stop if running
    try { await execAsync('service suricata stop 2>/dev/null') } catch(e) {}
    await new Promise(r => setTimeout(r, 1000))

    // Start
    await execAsync('service suricata start 2>/dev/null')
    return { success: true }
  } catch(e) { return { success: false, error: e.message } }
}

async function stop() {
  try {
    await execAsync('service suricata stop 2>/dev/null || pkill suricata 2>/dev/null || true')
    const settings = await getSettings()
    settings.enabled = false
    await saveSettings(settings)
    return { success: true }
  } catch(e) { return { success: false, error: e.message } }
}

async function getAlerts(limit = 100) {
  try {
    const { stdout } = await execAsync(`grep '"event_type":"alert"' ${EVE_LOG} 2>/dev/null | tail -${limit} || echo ""`)
    if (!stdout.trim()) return []
    const alerts = []
    for (const line of stdout.trim().split('\n')) {
      try {
        const evt = JSON.parse(line)
        alerts.push({
          timestamp: evt.timestamp,
          srcIP: evt.src_ip,
          srcPort: evt.src_port,
          dstIP: evt.dest_ip,
          dstPort: evt.dest_port,
          proto: evt.proto,
          category: evt.alert?.category,
          signature: evt.alert?.signature,
          severity: evt.alert?.severity,
          action: evt.alert?.action,
          http: evt.http ? {
            method: evt.http.http_method,
            url: evt.http.url,
            userAgent: evt.http.http_user_agent,
            status: evt.http.status
          } : null,
          payload: evt.payload_printable ? evt.payload_printable.substring(0, 200) : null
        })
      } catch(e) {}
    }
    return alerts.reverse()
  } catch(e) { return [] }
}

async function clearAlerts() {
  try {
    await fs.writeFile(EVE_LOG, '')
    await fs.writeFile(FAST_LOG, '').catch(() => {})
    return { success: true }
  } catch(e) { return { success: false, error: e.message } }
}

module.exports = {
  getSettings, saveSettings, getInterfaces,
  getStatus, start, stop,
  getAlerts, clearAlerts
}
