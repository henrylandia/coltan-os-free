'use strict'

const { exec } = require('child_process')
const { promisify } = require('util')
const execAsync = promisify(exec)
const fs = require('fs')

const EVE_LOG = '/var/log/suricata/eve.json'
const SETTINGS_FILE = '/usr/local/etc/coltan/suricata.json'
const BLOCKED_IPS_FILE = '/usr/local/etc/coltan/blocked-ips.json'

const CATEGORY_MAP = {
  scan: ['Detection of a Network Scan', 'Network Scan'],
  dos: ['Attempted Denial of Service', 'Denial of Service'],
  malware: ['A Network Trojan was Detected', 'Malware'],
  botcc: ['Botnet Command and Control Activity', 'CnC'],
  exploit: ['Attempted Administrator Privilege Gain', 'Attempted User Privilege Gain'],
  trojan: ['A Network Trojan was Detected', 'Backdoor'],
  policy: ['Policy Violation'],
  web: ['Web Application Attack', 'Attempted Information Leak']
}

let watcher = null
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

async function blockIP(ip, reason) {
  try {
    if (!ip) return
    const list = getBlockedIPs()
    if (list.find(i => i.ip === ip)) {
      console.log(`[AutoBlock] Already blocked: ${ip}`)
      return
    }

    list.push({ ip, description: `Auto-blocked: ${reason}`, addedAt: new Date().toISOString() })
    fs.writeFileSync(BLOCKED_IPS_FILE, JSON.stringify(list, null, 2))

    // Apply to PF immediately - add to table AND reload rules
    await execAsync(`pfctl -t blocked -T add ${ip} 2>/dev/null || true`)
    // Also regenerate full pf.conf so it persists after reboot
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
        if (category.toLowerCase().includes(cat.toLowerCase())) {
          return key
        }
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
    if (!settings.autoBlock || !settings.autoBlock.enabled) {
      return
    }

    const category = evt.alert?.category || ''
    const matchedKey = shouldBlock(category, settings.autoBlock.categories)
    
    console.log(`[AutoBlock] Alert: ${evt.src_ip} — ${category} — match: ${matchedKey}`)
    
    if (matchedKey) {
      await blockIP(evt.src_ip, `${evt.alert?.signature} (${category})`)
    }
  } catch(e) {}
}

function startWatcher() {
  if (watcher) return

  try {
    const stat = fs.statSync(EVE_LOG)
    filePosition = stat.size
  } catch(e) { filePosition = 0 }

  console.log(`[AutoBlock] Watcher started on ${EVE_LOG} at position ${filePosition}`)

  watcher = fs.watch(EVE_LOG, (event) => {
    if (event !== 'change') return
    try {
      const stat = fs.statSync(EVE_LOG)
      if (stat.size <= filePosition) { filePosition = 0; return }

      const buf = Buffer.alloc(stat.size - filePosition)
      const fd = fs.openSync(EVE_LOG, 'r')
      fs.readSync(fd, buf, 0, buf.length, filePosition)
      fs.closeSync(fd)
      filePosition = stat.size

      const lines = buf.toString().split('\n').filter(l => l.trim())
      lines.forEach(line => processLine(line))
    } catch(e) {
      console.error('[AutoBlock] Watch error:', e.message)
    }
  })
}

function stopWatcher() {
  if (watcher) { watcher.close(); watcher = null }
  console.log('[AutoBlock] Watcher stopped')
}

module.exports = { startWatcher, stopWatcher }
