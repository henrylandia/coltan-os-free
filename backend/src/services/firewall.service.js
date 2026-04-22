'use strict'

const { exec } = require('child_process')
const { promisify } = require('util')
const execAsync = promisify(exec)
const fs = require('fs').promises

const PF_CONF = '/etc/pf.conf'
const RULES_FILE = '/usr/local/etc/coltan/firewall-rules.json'
const BLOCKED_IPS_FILE = '/usr/local/etc/coltan/blocked-ips.json'
const PORT_FORWARD_FILE = '/usr/local/etc/coltan/port-forwards.json'

async function ensureDir() {
  await execAsync('mkdir -p /usr/local/etc/coltan')
}

// ─── INTERFACES ───────────────────────────────────────────────────────────────

async function getIfaceRoles() {
  try {
    const content = await fs.readFile('/usr/local/etc/coltan/interfaces.json', 'utf8')
    return JSON.parse(content)
  } catch(e) { return {} }
}

async function getWanIface() {
  const roles = await getIfaceRoles()
  return Object.entries(roles).find(([, v]) => v.role === 'WAN')?.[0] || 're0'
}

async function getLanIfaces() {
  const roles = await getIfaceRoles()
  return Object.entries(roles)
    .filter(([, v]) => v.role === 'LAN' || v.role?.startsWith('OPT'))
    .map(([name]) => name)
}

// ─── RULES ────────────────────────────────────────────────────────────────────

async function getRules() {
  try {
    await ensureDir()
    const content = await fs.readFile(RULES_FILE, 'utf8')
    return JSON.parse(content)
  } catch(e) { return [] }
}

async function saveRules(rules) {
  await ensureDir()
  await fs.writeFile(RULES_FILE, JSON.stringify(rules, null, 2))
}

async function addRule(rule) {
  const rules = await getRules()
  const newRule = {
    id: Date.now().toString(),
    enabled: true,
    action: rule.action || 'pass',
    direction: rule.direction || 'in',
    protocol: rule.protocol || 'tcp',
    interface: rule.interface || 'any',
    srcAddr: rule.srcAddr || 'any',
    srcPort: rule.srcPort || '',
    dstAddr: rule.dstAddr || 'any',
    dstPort: rule.dstPort || '',
    description: rule.description || '',
    createdAt: new Date().toISOString()
  }
  rules.push(newRule)
  await saveRules(rules)
  await generateAndReload()
  return { success: true, rule: newRule }
}

async function deleteRule(id) {
  const rules = await getRules()
  const filtered = rules.filter(r => r.id !== id)
  await saveRules(filtered)
  await generateAndReload()
  return { success: true }
}

async function toggleRule(id) {
  const rules = await getRules()
  const rule = rules.find(r => r.id === id)
  if (!rule) return { success: false, error: 'Rule not found' }
  rule.enabled = !rule.enabled
  await saveRules(rules)
  await generateAndReload()
  return { success: true, enabled: rule.enabled }
}

// ─── BLOCKED IPs ──────────────────────────────────────────────────────────────

async function getBlockedIPs() {
  try {
    const content = await fs.readFile(BLOCKED_IPS_FILE, 'utf8')
    return JSON.parse(content)
  } catch(e) { return [] }
}

async function blockIP(ip, description) {
  const list = await getBlockedIPs()
  if (list.find(i => i.ip === ip)) return { success: false, error: 'IP already blocked' }
  list.push({ ip, description: description || '', addedAt: new Date().toISOString() })
  await fs.writeFile(BLOCKED_IPS_FILE, JSON.stringify(list, null, 2))
  await generateAndReload()
  return { success: true }
}

async function unblockIP(ip) {
  const list = await getBlockedIPs()
  const filtered = list.filter(i => i.ip !== ip)
  await fs.writeFile(BLOCKED_IPS_FILE, JSON.stringify(filtered, null, 2))
  await generateAndReload()
  return { success: true }
}

// ─── PORT FORWARDING ──────────────────────────────────────────────────────────

async function getPortForwards() {
  try {
    const content = await fs.readFile(PORT_FORWARD_FILE, 'utf8')
    return JSON.parse(content)
  } catch(e) { return [] }
}

async function addPortForward(pf) {
  const list = await getPortForwards()
  const entry = {
    id: Date.now().toString(),
    enabled: true,
    protocol: pf.protocol || 'tcp',
    extPort: pf.extPort,
    intIP: pf.intIP,
    intPort: pf.intPort,
    description: pf.description || ''
  }
  list.push(entry)
  await fs.writeFile(PORT_FORWARD_FILE, JSON.stringify(list, null, 2))
  await generateAndReload()
  return { success: true, entry }
}

async function deletePortForward(id) {
  const list = await getPortForwards()
  const filtered = list.filter(p => p.id !== id)
  await fs.writeFile(PORT_FORWARD_FILE, JSON.stringify(filtered, null, 2))
  await generateAndReload()
  return { success: true }
}

// ─── PF CONFIG GENERATOR ──────────────────────────────────────────────────────

async function generatePFConf() {
  const wan = await getWanIface()
  const lans = await getLanIfaces()
  const rules = await getRules()
  const blockedIPs = await getBlockedIPs()
  const portForwards = await getPortForwards()

  let conf = `# Coltan OS — PF Firewall (auto-generated)
# DO NOT EDIT MANUALLY — use the Coltan OS dashboard

# Interfaces
ext_if = "${wan}"
`
  lans.forEach((lan, i) => {
    conf += `lan_if${i === 0 ? '' : i} = "${lan}"\n`
  })

  conf += `
# Options
set block-policy drop
set skip on lo0

# Scrub
scrub in all

`

  // Blocked IPs table
  if (blockedIPs.length > 0) {
    conf += `# Blocked IPs\ntable <blocked> { ${blockedIPs.map(i => i.ip).join(', ')} }\nblock in quick from <blocked> to any\nblock out quick from any to <blocked>\n\n`
  }

  // NAT for each LAN
  lans.forEach((lan, i) => {
    const lanVar = `$lan_if${i === 0 ? '' : i}`
    conf += `nat on $ext_if from ${lanVar}:network to any -> ($ext_if)\n`
  })

  conf += `
# Default rules
block in all
pass out all keep state

# Allow SSH
pass in on $ext_if proto tcp to port 22 keep state

# Allow WebUI
pass in on $ext_if proto tcp to port 3000 keep state

# Allow Samba
pass in on $ext_if proto tcp to port { 139, 445 } keep state
pass in on $ext_if proto udp to port { 137, 138 } keep state

# Allow ICMP
pass in on $ext_if proto icmp keep state

# Allow HTTP/HTTPS
pass in on $ext_if proto tcp to port { 80, 443 } keep state

# Allow DHCP
pass in on $ext_if proto udp to port 67 keep state

`

  // LAN pass rules
  lans.forEach((lan, i) => {
    const lanVar = `$lan_if${i === 0 ? '' : i}`
    conf += `# Allow LAN ${lan} traffic\npass in on ${lanVar} from ${lanVar}:network to any keep state\npass out on $ext_if from ${lanVar}:network to any keep state\n\n`
  })

  // Port forwards
  const enabledForwards = portForwards.filter(p => p.enabled)
  if (enabledForwards.length > 0) {
    conf += `# Port Forwarding\n`
    enabledForwards.forEach(p => {
      conf += `rdr on $ext_if proto ${p.protocol} from any to any port ${p.extPort} -> ${p.intIP} port ${p.intPort}\n`
      conf += `pass in on $ext_if proto ${p.protocol} from any to ${p.intIP} port ${p.intPort} keep state\n`
    })
    conf += '\n'
  }

  // Custom rules
  const enabledRules = rules.filter(r => r.enabled)
  if (enabledRules.length > 0) {
    conf += `# Custom Rules\n`
    enabledRules.forEach(r => {
      let rule = `${r.action} ${r.direction}`
      if (r.interface && r.interface !== 'any') rule += ` on ${r.interface}`
      if (r.protocol && r.protocol !== 'any') rule += ` proto ${r.protocol}`
      rule += ` from ${r.srcAddr || 'any'}`
      if (r.srcPort) rule += ` port ${r.srcPort}`
      rule += ` to ${r.dstAddr || 'any'}`
      if (r.dstPort) rule += ` port ${r.dstPort}`
      rule += ` keep state`
      if (r.description) rule += ` # ${r.description}`
      conf += rule + '\n'
    })
  }

  return conf
}

async function generateAndReload() {
  const conf = await generatePFConf()
  await fs.writeFile(PF_CONF, conf)
  try {
    await execAsync('pfctl -f /etc/pf.conf 2>/dev/null')
    await execAsync('pfctl -e 2>/dev/null')
  } catch(e) {}
  return { success: true }
}

// ─── STATUS ───────────────────────────────────────────────────────────────────

async function getStatus() {
  try {
    const { stdout } = await execAsync('pfctl -s info 2>/dev/null')
    const enabled = stdout.includes('Enabled')
    const stateMatch = stdout.match(/current entries\s+(\d+)/)
    const states = stateMatch ? parseInt(stateMatch[1]) : 0
    return { enabled, states }
  } catch(e) { return { enabled: false, states: 0 } }
}

async function getConfig() {
  try { return await fs.readFile(PF_CONF, 'utf8') } catch(e) { return '' }
}

async function saveConfig(content) {
  await fs.writeFile(PF_CONF, content)
  await execAsync('pfctl -f /etc/pf.conf 2>/dev/null')
  return { success: true }
}

async function enablePF() {
  await execAsync('pfctl -e 2>/dev/null')
  return { success: true }
}

async function disablePF() {
  await execAsync('pfctl -d 2>/dev/null')
  return { success: true }
}

async function getPFRules() {
  try {
    const { stdout } = await execAsync('pfctl -sr 2>/dev/null')
    return stdout.trim().split('\n').filter(l => l.trim()).map((rule, i) => ({ id: i + 1, rule }))
  } catch(e) { return [] }
}

module.exports = {
  getStatus, getConfig, saveConfig, enablePF, disablePF, getPFRules,
  getRules, addRule, deleteRule, toggleRule,
  getBlockedIPs, blockIP, unblockIP,
  getPortForwards, addPortForward, deletePortForward,
  generateAndReload, generatePFConf
}
