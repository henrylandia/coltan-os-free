'use strict'

const { exec } = require('child_process')
const { promisify } = require('util')
const execAsync = promisify(exec)
const fs = require('fs')

const EVE_LOG = '/var/log/suricata/eve.json'
const SETTINGS_FILE = '/usr/local/etc/coltan/suricata.json'
const BLOCKED_IPS_FILE = '/usr/local/etc/coltan/blocked-ips.json'
const WHITELIST_FILE = '/usr/local/etc/coltan/autoblock-whitelist.json'

const CATEGORY_MAP = {
  scan:    ['Detection of a Network Scan', 'Network Scan', 'Potentially Bad Traffic', 'Misc activity'],
  dos:     ['Attempted Denial of Service', 'Denial of Service'],
  malware: ['A Network Trojan was Detected', 'Malware', 'Trojan'],
  botcc:   ['Botnet Command and Control Activity', 'CnC'],
  exploit: ['Attempted Administrator Privilege Gain', 'Attempted User Privilege Gain', 'Exploit'],
  trojan:  ['A Network Trojan was Detected', 'Backdoor'],
  policy:  ['Policy Violation'],
  web:     ['Web Application Attack', 'Attempted Information Leak']
}

// IPs que NUNCA se bloquean
const BUILTIN_WHITELIST = [
  '127.0.0.1', '::1',
  '186.124.23.168', // sistema.coltanos.com IP publica
]

// Prefijos de redes privadas que nunca se bloquean
const PRIVATE_PREFIXES = ['192.168.', '10.', '172.16.', '172.17.', '172.18.',
  '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
  '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.']

let pollingInterval = null
let filePosition = 0

function getSettings() {
  try {
    return JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8'))
  } catch(e) { return { autoBlock: { enabled: false, categories: {} } } }
}

function getBlockedIPs() {
  try {
    return JSON.parse(fs.readFileSync(BLOCKED_IPS_FILE, 'utf8'))
  } catch(e) { return [] }
}

function getWhitelist() {
  try {
    return JSON.parse(fs.readFileSync(WHITELIST_FILE, 'utf8'))
  } catch(e) { return [] }
}

function isWhitelisted(ip) {
  if (!ip) return true
  // Redes privadas nunca se bloquean
  for (const prefix of PRIVATE_PREFIXES) {
    if (ip.startsWith(prefix)) return true
  }
  // Whitelist builtin
  if (BUILTIN_WHITELIST.includes(ip)) return true
  // Whitelist del usuario
  const userWhitelist = getWhitelist()
  if (userWhitelist.includes(ip)) return true
  return false
}

async function blockIP(ip, reason) {
  try {
    if (!ip) return
    if (isWhitelisted(ip)) {
      console.log(`[AutoBlock] Skipped (whitelisted): ${ip}`)
      return
    }
    const list = getBlockedIPs()
    if (list.find(i => i.ip === ip)) {
      console.log(`[AutoBlock] Already blocked: ${ip}`)
      return
    }
    list.push({ ip, description: `Auto-blocked: ${reason}`, addedAt: new Date().toISOString() })
    fs.writeFileSync(BLOCKED_IPS_FILE, JSON.stringify(list, null, 2))
    await execAsync(`pfctl -t blocked -T add ${ip} 2>/dev/null || true`)
    try {
      const { generateAndReload } = require('./firewall.service')
      generateAndReload().catch(() => {})
    } catch(e) {}
    console.log(`[AutoBlock] BLOCKED: ${ip} — ${reason}`)
  } catch(e) {
    console.error('[AutoBlock] Error blocking IP:', e.message)
  }
}

function shouldBlock(category, autoBlockCategories) {
  if (!category || !autoBlockCategories) return null
  for (const [key, cats] of Object.entries(CATEGORY_MAP)) {
    if (autoBlockCategories[key]) {
      for (const cat of cats) {
        if (category.toLowerCase().includes(cat.toLowerCase())) return key
      }
    }
  }
  return null
}

async function processLine(line) {
  if (!line.trim()) return
  try {
    const evt = JSON.parse(line)
    if (evt.event_type !== 'alert') return
    if (!evt.src_ip) return
    const settings = getSettings()
    if (!settings.autoBlock || !settings.autoBlock.enabled) return
    const category = evt.alert?.category || ''
    const matchedKey = shouldBlock(category, settings.autoBlock.categories)
    console.log(`[AutoBlock] Alert: ${evt.src_ip} — ${category} — match: ${matchedKey}`)
    if (matchedKey) {
      await blockIP(evt.src_ip, `${evt.alert?.signature} (${category})`)
    }
  } catch(e) {}
}

async function processNewLines() {
  try {
    if (!fs.existsSync(EVE_LOG)) return
    const stat = fs.statSync(EVE_LOG)
    if (stat.size < filePosition) {
      console.log('[AutoBlock] Log rotado, reseteando posicion')
      filePosition = 0
    }
    if (stat.size === filePosition) return
    const buf = Buffer.alloc(stat.size - filePosition)
    const fd = fs.openSync(EVE_LOG, 'r')
    fs.readSync(fd, buf, 0, buf.length, filePosition)
    fs.closeSync(fd)
    filePosition = stat.size
    const lines = buf.toString().split('\n').filter(l => l.trim())
    for (const line of lines) {
      await processLine(line)
    }
  } catch(e) {
    console.error('[AutoBlock] Poll error:', e.message)
  }
}

async function processRecentAlerts() {
  try {
    if (!fs.existsSync(EVE_LOG)) return
    const content = fs.readFileSync(EVE_LOG, 'utf8')
    const lines = content.split('\n').filter(l => l.trim())
    const cutoff = Date.now() - 2 * 60 * 60 * 1000
    const blockedIPs = getBlockedIPs().map(i => i.ip)
    for (const line of lines) {
      try {
        const evt = JSON.parse(line)
        if (evt.event_type !== 'alert') continue
        if (!evt.src_ip) continue
        if (blockedIPs.includes(evt.src_ip)) continue
        if (isWhitelisted(evt.src_ip)) continue
        const evtTime = new Date(evt.timestamp).getTime()
        if (evtTime < cutoff) continue
        const settings = getSettings()
        if (!settings.autoBlock || !settings.autoBlock.enabled) continue
        const category = evt.alert?.category || ''
        const matchedKey = shouldBlock(category, settings.autoBlock.categories)
        if (matchedKey) {
          console.log(`[AutoBlock] Alerta reciente: ${evt.src_ip} — ${category}`)
          await blockIP(evt.src_ip, `${evt.alert?.signature} (${category})`)
        }
      } catch(e) {}
    }
    console.log('[AutoBlock] Procesamiento de alertas recientes completado')
  } catch(e) {
    console.error('[AutoBlock] Error procesando alertas recientes:', e.message)
  }
}

function startWatcher() {
  if (pollingInterval) return
  console.log(`[AutoBlock] Iniciando polling en ${EVE_LOG}`)
  processRecentAlerts().then(() => {
    try {
      const stat = fs.statSync(EVE_LOG)
      filePosition = stat.size
    } catch(e) { filePosition = 0 }
    console.log(`[AutoBlock] Posicion inicial: ${filePosition} bytes`)
  })
  // Polling cada 5 segundos - mas confiable que fs.watch en FreeBSD
  pollingInterval = setInterval(processNewLines, 5000)
}

function stopWatcher() {
  if (pollingInterval) { clearInterval(pollingInterval); pollingInterval = null }
  console.log('[AutoBlock] Watcher detenido')
}

module.exports = { startWatcher, stopWatcher, blockIP, isWhitelisted }
