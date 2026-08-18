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
    // Malware, troyanos, spyware
    '  - /usr/local/etc/suricata/rules/emerging-malware.rules',
    '  - /usr/local/etc/suricata/rules/emerging-mobile_malware.rules',
    '  - /usr/local/etc/suricata/rules/emerging-coinminer.rules',
    // Botnets y comando-y-control (C2) -- ransomware y malware moderno usan esto
    '  - /usr/local/etc/suricata/rules/botcc.rules',
    '  - /usr/local/etc/suricata/rules/threatview_CS_c2.rules',
    // Exploits, shellcode, kits de explotacion
    '  - /usr/local/etc/suricata/rules/emerging-exploit.rules',
    '  - /usr/local/etc/suricata/rules/emerging-exploit_kit.rules',
    '  - /usr/local/etc/suricata/rules/emerging-shellcode.rules',
    // Amenazas activas recientes (incluye variantes de ransomware conocidas)
    '  - /usr/local/etc/suricata/rules/emerging-current_events.rules',
    // Worms
    '  - /usr/local/etc/suricata/rules/emerging-worm.rules',
    // Ataques web: SQL injection, webshells, XSS, apps especificas vulnerables
    '  - /usr/local/etc/suricata/rules/emerging-web_server.rules',
    '  - /usr/local/etc/suricata/rules/emerging-web_client.rules',
    '  - /usr/local/etc/suricata/rules/emerging-web_specific_apps.rules',
    '  - /usr/local/etc/suricata/rules/emerging-sql.rules',
    // Escaneos de puertos y reconocimiento
    '  - /usr/local/etc/suricata/rules/emerging-scan.rules',
    '  - /usr/local/etc/suricata/rules/emerging-user_agents.rules',
    // Denegacion de servicio
    '  - /usr/local/etc/suricata/rules/emerging-dos.rules',
    // Senales de sistema ya comprometido (indicador de ataque exitoso)
    '  - /usr/local/etc/suricata/rules/emerging-attack_response.rules',
    // Phishing
    '  - /usr/local/etc/suricata/rules/emerging-phishing.rules',
    // Fuerza bruta y explotacion de servicios comunes (FTP, Telnet, RPC, NetBIOS)
    '  - /usr/local/etc/suricata/rules/emerging-ftp.rules',
    '  - /usr/local/etc/suricata/rules/emerging-telnet.rules',
    '  - /usr/local/etc/suricata/rules/emerging-rpc.rules',
    '  - /usr/local/etc/suricata/rules/emerging-netbios.rules',
    // Uso de Tor (posible evasion/exfiltracion)
    '  - /usr/local/etc/suricata/rules/tor.rules',
    // Listas de IPs maliciosas conocidas (C2, bots, escaneadores, comprometidas)
    '  - /usr/local/etc/suricata/rules/compromised.rules',
    '  - /usr/local/etc/suricata/rules/dshield.rules',
    '  - /usr/local/etc/suricata/rules/ciarmy.rules',
    '  - /usr/local/etc/suricata/rules/drop.rules',
    // NOTA: emerging-policy.rules y emerging-p2p.rules quedan EXCLUIDAS a proposito --
    // esas categorias detectan uso de aplicaciones (Spotify, juegos, P2P, chat, etc),
    // no ataques. Generaban ruido sin valor de seguridad real.
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
    ORACLE_PORTS: 1521
    MODBUS_PORTS: 502
    FTP_PORTS: 21
    FILE_DATA_PORTS: "[80,110,143]"
    SIP_PORTS: "[5060,5061]"
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
    // service suricata restart puede dejar residuos de config vieja en memoria en FreeBSD.
    // stop + start por separado garantiza una recarga 100% limpia del yaml y las reglas.
    await execAsync('service suricata stop 2>/dev/null || true')
    await new Promise(r => setTimeout(r, 1500))
    await execAsync('service suricata start 2>&1')
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

// Taxonomia de amenazas: mapea las categorias crudas de Suricata/ET a un tipo
// de ataque claro y profesional para mostrar en el panel y poder filtrar.
const THREAT_TAXONOMY = [
  { key: 'malware',   label: 'Malware / Troyanos',        icon: '🦠', match: ['trojan', 'malware', 'spyware', 'adware'] },
  { key: 'ransomware',label: 'Ransomware',                 icon: '🔒', match: ['ransomware'] },
  { key: 'botnet',    label: 'Botnet / Comando y Control', icon: '🕸️', match: ['command and control', 'botnet', 'cnc', 'c2'] },
  { key: 'exploit',   label: 'Exploits',                   icon: '💥', match: ['exploit', 'privilege gain', 'shellcode', 'buffer overflow'] },
  { key: 'webattack', label: 'Ataques Web (SQLi/XSS/Webshell)', icon: '🌐', match: ['web application attack', 'sql injection', 'webshell', 'cross site'] },
  { key: 'scan',      label: 'Escaneos / Reconocimiento',  icon: '🔍', match: ['network scan', 'potentially bad traffic'] },
  { key: 'dos',       label: 'Denegación de Servicio (DoS)', icon: '⚡', match: ['denial of service'] },
  { key: 'bruteforce',label: 'Fuerza Bruta',                icon: '🔨', match: ['brute force', 'attempted user'] },
  { key: 'phishing',  label: 'Phishing',                    icon: '🎣', match: ['phishing'] },
  { key: 'worm',      label: 'Worms',                       icon: '🪱', match: ['worm'] },
  { key: 'evasion',   label: 'Evasión / Tor / Anonimización', icon: '🥷', match: ['tor', 'anonymiz'] },
  { key: 'malicious_ip', label: 'IP Maliciosa Conocida',     icon: '🚫', match: ['misc attack', 'known compromised', 'blacklist'] },
  { key: 'info_leak', label: 'Fuga de Información',          icon: '📤', match: ['information leak'] },
]

function classifyAlert(category) {
  if (!category) return { key: 'other', label: 'Otro / Sin clasificar', icon: '❓' }
  const lower = category.toLowerCase()
  for (const t of THREAT_TAXONOMY) {
    if (t.match.some(m => lower.includes(m))) return { key: t.key, label: t.label, icon: t.icon }
  }
  return { key: 'other', label: 'Otro / Sin clasificar', icon: '❓' }
}

async function getAlerts(limit = 100, categoryFilter = null) {
  try {
    // Nunca leer el archivo completo: en equipos con mucho trafico eve.json puede
    // pesar cientos de MB y hacer explotar el heap de Node. Usamos tail (sin carga
    // en memoria de Node) trayendo bastantes mas lineas que el limit pedido, para
    // tener margen suficiente despues de aplicar los filtros de categoria.
    const tailLines = Math.max(limit * 20, 5000)
    let content = ''
    try {
      const { stdout } = await execAsync(`tail -n ${tailLines} ${EVE_LOG}`)
      content = stdout
    } catch(e) { return [] }
    const lines = content.trim().split('\n').filter(Boolean)
    const alerts = []
    for (let i = lines.length - 1; i >= 0 && alerts.length < limit; i--) {
      try {
        const evt = JSON.parse(lines[i])
        if (evt.event_type !== 'alert') continue
        const classification = classifyAlert(evt.alert?.category)
        if (categoryFilter && categoryFilter !== 'all' && classification.key !== categoryFilter) continue
        // Normalizamos el formato crudo de Suricata (snake_case, campos anidados en "alert")
        // al formato que espera el frontend (camelCase, campos planos).
        const normalized = {
          timestamp: evt.timestamp,
          srcIP: evt.src_ip,
          srcPort: evt.src_port,
          dstIP: evt.dest_ip,
          dstPort: evt.dest_port,
          proto: evt.proto,
          action: evt.alert?.action,
          severity: evt.alert?.severity,
          signature: evt.alert?.signature,
          category: evt.alert?.category,
          http: evt.http ? { method: evt.http.http_method, url: evt.http.url, userAgent: evt.http.http_user_agent } : null,
          payload: evt.payload_printable || null,
          _threatType: classification
        }
        alerts.push(normalized)
      } catch(e) {}
    }
    return alerts
  } catch(e) { return [] }
}

// Devuelve el conteo de alertas agrupadas por tipo de amenaza, para mostrar
// los filtros con su cantidad en el panel.
async function getAlertStats() {
  try {
    // Mismo motivo que getAlerts: nunca leer el archivo completo con readFile.
    let content = ''
    try {
      const { stdout } = await execAsync(`tail -n 20000 ${EVE_LOG}`)
      content = stdout
    } catch(e) { return { total: 0, byType: [] } }
    const lines = content.trim().split('\n').filter(Boolean)
    const counts = {}
    let total = 0
    for (const line of lines) {
      try {
        const evt = JSON.parse(line)
        if (evt.event_type !== 'alert') continue
        total++
        const classification = classifyAlert(evt.alert?.category)
        counts[classification.key] = (counts[classification.key] || 0) + 1
      } catch(e) {}
    }
    const byType = THREAT_TAXONOMY.map(t => ({ key: t.key, label: t.label, icon: t.icon, count: counts[t.key] || 0 }))
      .filter(t => t.count > 0)
    if (counts['other']) byType.push({ key: 'other', label: 'Otro / Sin clasificar', icon: '❓', count: counts['other'] })
    byType.sort((a,b) => b.count - a.count)
    return { total, byType }
  } catch(e) { return { total: 0, byType: [] } }
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
  getAlerts, clearAlerts, getAlertStats,
  classifyAlert, THREAT_TAXONOMY
}
