'use strict'
const { exec } = require('child_process')
const { promisify } = require('util')
const execAsync = promisify(exec)
const fs = require('fs')
const http = require('http')
const { getDB } = require('./db.service')

// ─── TRAFFIC COLLECTOR ────────────────────────────────────────────────────────
let _prevTraffic = {}

async function collectTraffic() {
  try {
    const { stdout } = await execAsync('netstat -inb | grep -v lo0 | grep -v Link | grep -v Name')
    const db = getDB()
    const now = Math.floor(Date.now() / 1000)
    const stmt = db.prepare(`INSERT INTO traffic_samples (interface, rx_bytes, tx_bytes, rx_delta, tx_delta, sampled_at) VALUES (?, ?, ?, ?, ?, ?)`)

    stdout.trim().split('\n').forEach(line => {
      const parts = line.trim().split(/\s+/)
      if (parts.length < 10) return
      const iface = parts[0].replace(/\*$/, '')
      if (!iface.match(/^(re|em|bge|igb|wg|tun|vlan)/)) return
      const rxBytes = parseInt(parts[7]) || 0
      const txBytes = parseInt(parts[10]) || 0
      const prev = _prevTraffic[iface] || { rxBytes, txBytes }
      const rxDelta = Math.max(0, rxBytes - prev.rxBytes)
      const txDelta = Math.max(0, txBytes - prev.txBytes)
      _prevTraffic[iface] = { rxBytes, txBytes }
      stmt.run(iface, rxBytes, txBytes, rxDelta, txDelta, now)
    })
  } catch(e) {
    console.log('[Collector:Traffic] Error:', e.message)
  }
}

// ─── SURICATA COLLECTOR ───────────────────────────────────────────────────────
let _suricataPos = 0

function getGeoIP(ip) {
  return new Promise((resolve) => {
    http.get(`http://ip-api.com/json/${ip}?fields=status,country,countryCode,city,isp`, (res) => {
      let data = ''
      res.on('data', chunk => data += chunk)
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data)
          resolve(parsed.status === 'success' ? parsed : {})
        } catch(e) { resolve({}) }
      })
    }).on('error', () => resolve({}))
  })
}

async function collectSuricataAlerts() {
  const EVE_FILE = '/var/log/suricata/eve.json'
  if (!fs.existsSync(EVE_FILE)) return

  try {
    const stat = fs.statSync(EVE_FILE)

    // Si el archivo rotó o encogió, empezamos desde el final
    if (stat.size < _suricataPos) {
      _suricataPos = stat.size
      return
    }
    if (stat.size === _suricataPos) return

    const readSize = stat.size - _suricataPos
    if (readSize <= 0) return

    const fd = fs.openSync(EVE_FILE, 'r')
    const buf = Buffer.alloc(readSize)
    fs.readSync(fd, buf, 0, readSize, _suricataPos)
    fs.closeSync(fd)
    _suricataPos = stat.size

    const lines = buf.toString('utf8').split('\n').filter(Boolean)
    const db = getDB()
    const stmt = db.prepare(`
      INSERT INTO attack_log (src_ip, country, country_code, city, isp, attack_type, severity, signature, proto, dest_port, blocked, detected_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)

    // Geo cache para no llamar la API por cada alerta de la misma IP
    const geoCache = {}

    for (const line of lines) {
      try {
        const event = JSON.parse(line)
        if (event.event_type !== 'alert') continue

        const srcIP = event.src_ip
        if (!srcIP || srcIP.startsWith('192.168') || srcIP.startsWith('10.') || srcIP.startsWith('172.')) continue

        let geo = geoCache[srcIP]
        if (!geo) {
          geo = await getGeoIP(srcIP)
          geoCache[srcIP] = geo
        }

        const ts = Math.floor(new Date(event.timestamp).getTime() / 1000)
        stmt.run(
          srcIP,
          geo.country || null,
          geo.countryCode || null,
          geo.city || null,
          geo.isp || null,
          event.alert?.category || null,
          event.alert?.severity?.toString() || null,
          event.alert?.signature || null,
          event.proto || null,
          event.dest_port || null,
          0,
          ts || Math.floor(Date.now() / 1000)
        )
      } catch(e) {}
    }
  } catch(e) {
    console.log('[Collector:Suricata] Error:', e.message)
  }
}

// ─── PANEL ACCESS LOG ─────────────────────────────────────────────────────────
function logPanelAccess(username, ip, method, endpoint, statusCode, responseTime) {
  try {
    const db = getDB()
    db.prepare(`
      INSERT INTO panel_access_log (username, ip, method, endpoint, status_code, response_time, accessed_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(username || null, ip || null, method, endpoint, statusCode, responseTime, Math.floor(Date.now() / 1000))
  } catch(e) {}
}

// ─── START ALL COLLECTORS ─────────────────────────────────────────────────────
function startCollectors() {
  console.log('[Collectors] Iniciando collectors de analytics...')

  // Inicializar DB
  getDB()

  // Tráfico cada 60 segundos
  collectTraffic()
  setInterval(collectTraffic, 60 * 1000)

  // Suricata cada 30 segundos
  collectSuricataAlerts()
  setInterval(collectSuricataAlerts, 30 * 1000)

  console.log('[Collectors] OK — tráfico cada 60s, Suricata cada 30s')
}

module.exports = { startCollectors, logPanelAccess, collectTraffic, collectSuricataAlerts }
