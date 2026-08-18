'use strict'

const { exec } = require('child_process')
const { promisify } = require('util')
const execAsync = promisify(exec)
const fs = require('fs').promises

const SETTINGS_FILE = '/usr/local/etc/coltan/suricata.json'
const SURICATA_CONF = '/usr/local/etc/suricata/suricata.yaml'
const THRESHOLD_FILE = '/usr/local/etc/suricata/threshold.config'
const EVE_LOG = '/var/log/suricata/eve.json'
const FAST_LOG = '/var/log/suricata/fast.log'

async function ensureDir() {
  await execAsync('mkdir -p /usr/local/etc/coltan')
}

async function getSettings() {
  try {
    await ensureDir()
    const content = await fs.readFile(SETTINGS_FILE, 'utf8')
    return JSON.parse(content)
  } catch(e) {
    return { interface: 're0', mode: 'ids', enabled: false }
  }
}

async function saveSettings(settings) {
  await ensureDir()
  await fs.writeFile(SETTINGS_FILE, JSON.stringify(settings, null, 2))
  await generateConfig(settings)
  return { success: true }
}

async function getInterfaces() {
  try {
    const { stdout } = await execAsync('ifconfig -l')
    return stdout.trim().split(/\s+/).filter(i => i !== 'lo0')
  } catch(e) { return [] }
}

// Genera el threshold.config con el suppress de trafico legitimo del propio sistema
// (heartbeat/geolocalizacion hacia ip-api.com). Usa gen_id/sig_id con guion bajo,
// que es la sintaxis correcta para este archivo (distinta a la del yaml principal).
// No depende de ninguna IP -- el SID 2022082 identifica la firma "ET POLICY External IP
// Lookup ip-api.com" sin importar la IP publica de cada instalacion de Coltan OS.
async function ensureThresholdConfig() {
  const content = `# Coltan OS - Umbrales y supresiones de alertas
# Generado automaticamente. No editar a mano, se sobreescribe en cada guardado de configuracion.
#
# Suprime la alerta de "External IP Lookup ip-api.com" que dispara el propio heartbeat
# de Coltan OS al consultar la geolocalizacion. No es un ataque real.
suppress gen_id 1, sig_id 2022082
`
  try {
    await execAsync('mkdir -p /usr/local/etc/suricata')
    await fs.writeFile(THRESHOLD_FILE, content)
  } catch(e) {}
}

async function generateConfig(settings) {
  await ensureThresholdConfig()

  const iface = settings.interface || 're0'
  const mode = settings.mode || 'ids'

  let ruleFiles = [
    '  - /usr/local/etc/suricata/rules/emerging-malware.rules',
    '  - /usr/local/etc/suricata/rules/botcc.rules',
    '  - /usr/local/etc/suricata/rules/emerging-exploit.rules',
    '  - /usr/local/etc/suricata/rules/emerging-trojan.rules',
    '  - /usr/local/etc/suricata/rules/emerging-scan.rules',
    '  - /usr/local/etc/suricata/rules/emerging-user_agents.rules',
  ]

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
threshold-file: /usr/local/etc/suricata/threshold.config
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
  const settings = await getSettings()
  let running = false
  let pid = null
  try {
    const { stdout } = await execAsync('pgrep suricata')
    running = stdout.trim().length > 0
    pid = stdout.trim().split('\n')[0]
  } catch(e) { running = false }

  let alertCount = 0
  try {
    const { stdout } = await execAsync(`grep -c '"event_type":"alert"' ${EVE_LOG} 2>/dev/null || echo 0`)
    alertCount = parseInt(stdout.trim()) || 0
  } catch(e) {}

  return {
    running,
    pid,
    mode: settings.mode || 'ids',
    interface: settings.interface || 're0',
    alerts: alertCount
  }
}

async function start() {
  try {
    const settings = await getSettings()
    settings.enabled = true
    await saveSettings(settings)
    await execAsync('service suricata restart 2>&1')
    return { success: true }
  } catch(e) { return { success: false, error: e.message } }
}

async function stop() {
  try {
    const settings = await getSettings()
    settings.enabled = false
    await saveSettings(settings)
    await execAsync('service suricata stop 2>/dev/null')
    return { success: true }
  } catch(e) { return { success: false, error: e.message } }
}

async function getAlerts(limit = 100) {
  try {
    const content = await fs.readFile(EVE_LOG, 'utf8')
    const lines = content.trim().split('\n').filter(Boolean)
    const alerts = []
    for (let i = lines.length - 1; i >= 0 && alerts.length < limit; i--) {
      try {
        const evt = JSON.parse(lines[i])
        if (evt.event_type === 'alert') alerts.push(evt)
      } catch(e) {}
    }
    return alerts
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
