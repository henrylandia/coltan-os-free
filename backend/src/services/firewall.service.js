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

// ─── DEFAULT RULES ────────────────────────────────────────────────────────────

function makeRule(id, action, direction, protocol, iface, srcAddr, srcPort, dstAddr, dstPort, description, system = false) {
  return {
    id, enabled: true, system, action, direction, protocol,
    interface: iface, srcAddr, srcPort, dstAddr, dstPort, description,
    createdAt: new Date().toISOString()
  }
}

async function getDefaultRules(wan, lans) {
  const rules = [
    makeRule('sys-icmp', 'pass', 'in', 'icmp', wan, 'any', '', 'any', '', 'Allow ICMP (ping)', true),
    makeRule('sys-webui-wan', 'pass', 'in', 'tcp', wan, 'any', '', 'any', '3000', 'Allow Coltan OS WebUI (WAN)', true),
    makeRule('sys-http', 'pass', 'in', 'tcp', wan, 'any', '', 'any', '80', 'Allow HTTP', true),
    makeRule('sys-https', 'pass', 'in', 'tcp', wan, 'any', '', 'any', '443', 'Allow HTTPS', true),
    makeRule('sys-samba-tcp', 'pass', 'in', 'tcp', wan, 'any', '', 'any', '{ 139, 445 }', 'Allow Samba TCP', true),
    makeRule('sys-samba-udp', 'pass', 'in', 'udp', wan, 'any', '', 'any', '{ 137, 138 }', 'Allow Samba UDP', true),
    makeRule('sys-dhcp', 'pass', 'in', 'udp', wan, 'any', '', 'any', '67', 'Allow DHCP', true),
    makeRule('sys-wireguard', 'pass', 'in', 'udp', wan, 'any', '', 'any', '51820', 'Allow WireGuard VPN', true),
    makeRule('sys-openvpn', 'pass', 'in', 'udp', wan, 'any', '', 'any', '1194', 'Allow OpenVPN', true),
    makeRule('sys-ssh', 'pass', 'in', 'tcp', wan, 'any', '', 'any', '22', 'Allow SSH', true),
  ]

  // Check which LAN interfaces have an active captive portal
  let captiveIfaces = []
  try {
    const portals = JSON.parse(require('fs').readFileSync('/usr/local/etc/coltan/captive/portals.json', 'utf8'))
    captiveIfaces = portals.filter(p => p.enabled).map(p => p.interface)
  } catch(e) {}

  lans.forEach(lan => {
    if (!captiveIfaces.includes(lan)) {
      // No captive portal on this interface — allow all LAN traffic
      rules.push(makeRule(`sys-lan-${lan}`, 'pass', 'in', 'any', lan, 'any', '', 'any', '', `Allow all LAN traffic (${lan})`, true))
    }
    // Always allow WebUI access from LAN
    rules.push(makeRule(`sys-webui-lan-${lan}`, 'pass', 'in', 'tcp', lan, 'any', '', 'any', '3000', `Allow WebUI from LAN (${lan})`, true))
  })
  return rules
}

// ─── RULES ────────────────────────────────────────────────────────────────────

async function getRules() {
  await ensureDir()
  const wan = await getWanIface()
  const lans = await getLanIfaces()
  let saved = []
  try {
    const raw = await fs.readFile(RULES_FILE, 'utf8')
    saved = JSON.parse(raw)
  } catch(e) {}
  const systemRules = await getDefaultRules(wan, lans)
  const customRules = saved.filter(r => !r.system)
  return [...systemRules, ...customRules]
}

async function getRulesRaw() {
  try {
    await ensureDir()
    const content = await fs.readFile(RULES_FILE, 'utf8')
    return JSON.parse(content)
  } catch(e) { return [] }
}

async function saveRules(rules) {
  await ensureDir()
  const customOnly = rules.filter(r => !r.system)
  await fs.writeFile(RULES_FILE, JSON.stringify(customOnly, null, 2))
}

async function addRule(rule) {
  const rules = await getRules()
  const newRule = {
    id: Date.now().toString(), enabled: true, system: false,
    action: rule.action || 'pass', direction: rule.direction || 'in',
    protocol: rule.protocol || 'tcp', interface: rule.interface || 'any',
    srcAddr: rule.srcAddr || 'any', srcPort: rule.srcPort || '',
    dstAddr: rule.dstAddr || 'any', dstPort: rule.dstPort || '',
    description: rule.description || '', createdAt: new Date().toISOString()
  }
  rules.push(newRule)
  await saveRules(rules)
  await generateAndReload()
  return { success: true, rule: newRule }
}

async function updateRule(id, data) {
  const rules = await getRules()
  const idx = rules.findIndex(r => r.id === id)
  if (idx === -1) return { success: false, error: 'Rule not found' }
  rules[idx] = { ...rules[idx], ...data }
  await saveRules(rules)
  await generateAndReload()
  return { success: true }
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

async function reorderRules(ids) {
  const rules = await getRules()
  const ordered = ids.map(id => rules.find(r => r.id === id)).filter(Boolean)
  await saveRules(ordered)
  await generateAndReload()
  return { success: true }
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
    id: Date.now().toString(), enabled: true,
    protocol: pf.protocol || 'tcp',
    extPort: pf.extPort, intIP: pf.intIP, intPort: pf.intPort,
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
set skip on wg0

# Scrub
scrub in all

`

  // ── 1. NAT (must come before filtering) ──────────────────────────────────
  for (const lan of lans) {
    conf += `nat on $ext_if from ${lan}:network to any -> ($ext_if)\n`
  }

  // NAT for WireGuard
  try {
    const wgConfigRaw = require('fs').readFileSync('/usr/local/etc/coltan/wg-config.json', 'utf8')
    const wgConfig = JSON.parse(wgConfigRaw)
    const wgNet = wgConfig.serverIP ? wgConfig.serverIP.replace(/\.\d+\/\d+$/, '.0/24') : '10.0.0.0/24'
    conf += `nat on $ext_if from ${wgNet} to any -> ($ext_if)\n`
    conf += `pass in on wg0 from ${wgNet} to any keep state\n`
    conf += `pass out on $ext_if from ${wgNet} to any keep state\n`
    lans.forEach((lan, i) => {
      const lanVar = `$lan_if${i === 0 ? '' : i}`
      conf += `pass in on wg0 from ${wgNet} to ${lanVar}:network keep state\n`
      conf += `pass out on ${lan} from ${wgNet} to ${lanVar}:network keep state\n`
    })
    conf += `pass in on wg0 proto icmp all keep state\n`
    conf += `pass out on wg0 proto icmp all keep state\n`
  } catch(e) {
    conf += `nat on $ext_if from 10.0.0.0/8 to any -> ($ext_if)\n`
    conf += `pass in on wg0 all keep state\n`
    conf += `pass out on wg0 all keep state\n`
  }

  // ── 2. Captive Portal rdr (must be in main pf.conf, not anchor) ───────────
  try {
    const portals = JSON.parse(require('fs').readFileSync('/usr/local/etc/coltan/captive/portals.json', 'utf8'))
    const enabledPortals = portals.filter(p => p.enabled)
    if (enabledPortals.length > 0) {
      conf += `\n# Captive Portal\ntable <captive_allowed> persist\n`
      for (const portal of enabledPortals) {
        conf += `rdr pass on ${portal.interface} proto tcp from any to any port 80 -> 127.0.0.1 port 4080\n`
      }
    }
  } catch(e) {}

  // ── 3. Port Forwards (rdr - translation, before filtering) ───────────────
  const enabledForwards = portForwards.filter(p => p.enabled)
  if (enabledForwards.length > 0) {
    conf += `\n# Port Forwarding\n`
    enabledForwards.forEach(p => {
      conf += `rdr on $ext_if proto ${p.protocol} from any to any port ${p.extPort} -> ${p.intIP} port ${p.intPort}\n`
    })
  }

  conf += `\n# Sites blocking anchor\nanchor "coltan/sites"\n`
  conf += `\n# Default: pass out, block only what's explicitly blocked\npass out all keep state\n`
  conf += `\n# WireGuard interface - allow all traffic\npass quick on wg0 all keep state\n`

  // ── 4. Blocked IPs (filtering - after NAT) ────────────────────────────────
  if (blockedIPs.length > 0) {
    conf += `\n# Blocked IPs\ntable <blocked> { ${blockedIPs.map(i => i.ip).join(', ')} }\nblock in quick from <blocked> to any\nblock out quick from any to <blocked>\n`
  }

  // ── 5. Port forward pass rules ────────────────────────────────────────────
  if (enabledForwards.length > 0) {
    enabledForwards.forEach(p => {
      conf += `pass in on $ext_if proto ${p.protocol} from any to ${p.intIP} port ${p.intPort} keep state\n`
    })
  }

  // ── 6. Captive portal filtering rules (allow authenticated, block rest) ───
  try {
    const portals = JSON.parse(require('fs').readFileSync('/usr/local/etc/coltan/captive/portals.json', 'utf8'))
    const enabledPortals = portals.filter(p => p.enabled)
    if (enabledPortals.length > 0) {
      conf += `\n# Captive Portal filtering\n`
      for (const portal of enabledPortals) {
        const iface = portal.interface
        conf += `pass quick on ${iface} from <captive_allowed> to any keep state\n`
        conf += `pass quick on ${iface} from any to <captive_allowed> keep state\n`
        conf += `pass quick on ${iface} proto udp from any to any port 53 keep state\n`
        conf += `pass quick on ${iface} proto udp from any to any port 67 keep state\n`
        conf += `pass quick on ${iface} to 127.0.0.1 port 4080 keep state\n`
        conf += `block in quick on ${iface} from any to any\n`
      }
    }
  } catch(e) {}

  // ── 7. Firewall rules (system + custom) ───────────────────────────────────
  const enabledRules = rules.filter(r => r.enabled)
  if (enabledRules.length > 0) {
    conf += `\n# Firewall Rules\n`
    enabledRules.forEach(r => {
      let rule = `${r.action} ${r.direction}`
      if (r.interface && r.interface !== 'any') {
        if (r.interface === wan) rule += ` on $ext_if`
        else {
          const lanIdx = lans.indexOf(r.interface)
          if (lanIdx >= 0) rule += ` on $lan_if${lanIdx === 0 ? '' : lanIdx}`
          else rule += ` on ${r.interface}`
        }
      }
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
    await execAsync('sysctl net.inet.ip.forwarding=1 2>/dev/null')
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
  getRules, addRule, updateRule, deleteRule, toggleRule, reorderRules,
  getBlockedIPs, blockIP, unblockIP,
  getPortForwards, addPortForward, deletePortForward,
  generateAndReload, generatePFConf
}
