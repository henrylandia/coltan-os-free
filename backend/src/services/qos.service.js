'use strict'

const { exec } = require('child_process')
const { promisify } = require('util')
const execAsync = promisify(exec)
const fs = require('fs').promises

const QOS_FILE = '/usr/local/etc/coltan/qos.json'
const QOS_PF_ANCHOR = '/etc/pf.qos.conf'

async function ensureDir() {
  await execAsync('mkdir -p /usr/local/etc/coltan')
}

// ─── CRUD ─────────────────────────────────────────────────────────────────────

async function getRules() {
  try {
    const content = await fs.readFile(QOS_FILE, 'utf8')
    return JSON.parse(content)
  } catch(e) { return [] }
}

async function saveRules(rules) {
  await ensureDir()
  await fs.writeFile(QOS_FILE, JSON.stringify(rules, null, 2))
}

async function addRule(data) {
  const rules = await getRules()
  const rule = {
    id: Date.now().toString(),
    enabled: true,
    name: data.name || 'QoS Rule',
    target: data.target,
    targetValue: data.targetValue,
    mac: data.mac || null,
    downloadKbps: parseInt(data.downloadKbps) || 0,
    uploadKbps: parseInt(data.uploadKbps) || 0,
    schedule: data.schedule || null,
    createdAt: new Date().toISOString()
  }
  rules.push(rule)
  await saveRules(rules)
  await applyQoS()
  return { success: true, rule }
}

async function updateRule(id, data) {
  const rules = await getRules()
  const idx = rules.findIndex(r => r.id === id)
  if (idx === -1) return { success: false, error: 'Rule not found' }
  rules[idx] = { ...rules[idx], ...data }
  await saveRules(rules)
  await applyQoS()
  return { success: true }
}

async function deleteRule(id) {
  const rules = await getRules()
  const filtered = rules.filter(r => r.id !== id)
  await saveRules(filtered)
  await applyQoS()
  return { success: true }
}

async function toggleRule(id) {
  const rules = await getRules()
  const rule = rules.find(r => r.id === id)
  if (!rule) return { success: false, error: 'Rule not found' }
  rule.enabled = !rule.enabled
  await saveRules(rules)
  await applyQoS()
  return { success: true, enabled: rule.enabled }
}

// ─── GET LAN INTERFACES ───────────────────────────────────────────────────────

async function getLanInterfaces() {
  try {
    const content = await fs.readFile('/usr/local/etc/coltan/interfaces.json', 'utf8')
    const ifaces = JSON.parse(content)
    return Object.entries(ifaces)
      .filter(([, v]) => v.role === 'LAN' || v.role?.startsWith('OPT') || v.vlan)
      .map(([name]) => name)
  } catch(e) { return ['re1'] }
}

async function getWanInterface() {
  try {
    const content = await fs.readFile('/usr/local/etc/coltan/interfaces.json', 'utf8')
    const ifaces = JSON.parse(content)
    const wan = Object.entries(ifaces).find(([, v]) => v.role === 'WAN')
    return wan ? wan[0] : 're0'
  } catch(e) { return 're0' }
}

// ─── APPLY QoS ────────────────────────────────────────────────────────────────

async function applyQoS() {
  const rules = await getRules()

  // Load dummynet (safe with PF — no ipfw)
  try { await execAsync('kldload dummynet 2>/dev/null || true') } catch(e) {}

  // Clear existing dummynet pipes
  try { await execAsync('dnctl pipe flush 2>/dev/null || true') } catch(e) {}

  const now = new Date()
  const enabledRules = rules.filter(r => {
    if (!r.enabled) return false
    if (!r.schedule) return true
    return isScheduleActive(r.schedule, now)
  })

  let conf = `# Coltan OS QoS (auto-generated)\n\n`

  if (enabledRules.length === 0) {
    await fs.writeFile(QOS_PF_ANCHOR, conf)
    try { await execAsync(`pfctl -a coltan/qos -f ${QOS_PF_ANCHOR} 2>/dev/null`) } catch(e) {}
    // Clear existing states
    try { await execAsync('pfctl -F states 2>/dev/null') } catch(e) {}
    return { success: true, applied: 0 }
  }

  const lanIfaces = await getLanInterfaces()
  const pfRules = []
  let pipeId = 1

  for (const rule of enabledRules) {
    const dlPipe = rule.downloadKbps > 0 ? pipeId++ : null
    const ulPipe = rule.uploadKbps > 0 ? pipeId++ : null

    // If only one direction, use same pipe for both slots
    const inPipe = dlPipe || ulPipe
    const outPipe = ulPipe || dlPipe

    // Configure pipes with dnctl
    if (dlPipe) {
      try { await execAsync(`dnctl pipe ${dlPipe} config bw ${rule.downloadKbps}Kbit/s 2>/dev/null`) } catch(e) {}
    }
    if (ulPipe && ulPipe !== dlPipe) {
      try { await execAsync(`dnctl pipe ${ulPipe} config bw ${rule.uploadKbps}Kbit/s 2>/dev/null`) } catch(e) {}
    }

    if (rule.target === 'interface') {
      // Interface-wide limit
      const iface = rule.targetValue
      pfRules.push(`pass in quick on ${iface} inet from any to any dnpipe (${inPipe}, ${outPipe}) # ${rule.name}`)

    } else {
      // IP or range — apply on all LAN interfaces
      const src = rule.targetValue

      for (const lan of lanIfaces) {
        // pass in on LAN from client — captures both upload and download
        // dnpipe (in_pipe, out_pipe): in_pipe=download (server->client), out_pipe=upload (client->server)
        pfRules.push(`pass in quick on ${lan} inet from ${src} to any dnpipe (${outPipe}, ${inPipe}) # ${rule.name} UL`)
        pfRules.push(`pass out quick on ${lan} inet from any to ${src} dnpipe (${inPipe}, ${outPipe}) # ${rule.name} DL`)
      }

      // MAC-based rule if provided
      if (rule.mac && rule.target === 'ip') {
        for (const lan of lanIfaces) {
          pfRules.push(`pass in quick on ${lan} from ${rule.mac} to any dnpipe (${outPipe}, ${inPipe}) # ${rule.name} MAC UL`)
          pfRules.push(`pass out quick on ${lan} from any to ${rule.mac} dnpipe (${inPipe}, ${outPipe}) # ${rule.name} MAC DL`)
        }
      }
    }
  }

  conf += pfRules.join('\n') + '\n'
  await fs.writeFile(QOS_PF_ANCHOR, conf)

  // Load into PF anchor
  try { await execAsync(`pfctl -a coltan/qos -f ${QOS_PF_ANCHOR} 2>/dev/null`) } catch(e) {}

  // Flush states so new rules take effect immediately
  try { await execAsync('pfctl -F states 2>/dev/null') } catch(e) {}

  // Ensure anchor is in main pf.conf
  try {
    const pfConf = await fs.readFile('/etc/pf.conf', 'utf8')
    if (!pfConf.includes('coltan/qos')) {
      const updated = pfConf.replace(
        'anchor "coltan/sites"',
        'anchor "coltan/sites"\nanchor "coltan/qos"'
      )
      await fs.writeFile('/etc/pf.conf', updated)
      await execAsync('pfctl -f /etc/pf.conf 2>/dev/null')
    }
  } catch(e) {}

  return { success: true, applied: enabledRules.length }
}

// ─── SCHEDULE ─────────────────────────────────────────────────────────────────

function isScheduleActive(schedule, now) {
  if (!schedule) return true
  if (schedule.days && schedule.days.length > 0) {
    if (!schedule.days.includes(now.getDay())) return false
  }
  if (schedule.startTime && schedule.endTime) {
    const nowMin = now.getHours() * 60 + now.getMinutes()
    const [sh, sm] = schedule.startTime.split(':').map(Number)
    const [eh, em] = schedule.endTime.split(':').map(Number)
    const startMin = sh * 60 + sm
    const endMin = eh * 60 + em
    if (startMin <= endMin) {
      if (nowMin < startMin || nowMin > endMin) return false
    } else {
      if (nowMin < startMin && nowMin > endMin) return false
    }
  }
  return true
}

// ─── STATS ────────────────────────────────────────────────────────────────────

async function getStats() {
  try {
    const { stdout } = await execAsync('netstat -ibn 2>/dev/null')
    const lines = stdout.trim().split('\n')
    const interfaces = []
    const seen = new Set()

    for (const line of lines.slice(1)) {
      const parts = line.trim().split(/\s+/)
      if (parts.length < 10) continue
      const name = parts[0]
      if (name === 'lo0' || name.startsWith('*') || seen.has(name)) continue
      seen.add(name)
      const rxBytes = parseInt(parts[6]) || 0
      const txBytes = parseInt(parts[9]) || 0
      if (rxBytes === 0 && txBytes === 0) continue
      interfaces.push({ name, rxBytes, txBytes })
    }

    interfaces.sort((a, b) => (b.rxBytes + b.txBytes) - (a.rxBytes + a.txBytes))
    return { interfaces }
  } catch(e) { return { interfaces: [] } }
}

// ─── RESTORE ON BOOT ─────────────────────────────────────────────────────────

async function restoreQoS() {
  try { await applyQoS(); return { success: true } }
  catch(e) { return { success: false, error: e.message } }
}

module.exports = { getRules, addRule, updateRule, deleteRule, toggleRule, applyQoS, restoreQoS, getStats }
