'use strict'

const { exec } = require('child_process')
const { promisify } = require('util')
const execAsync = promisify(exec)
const fs = require('fs').promises

const IFACES_FILE = '/usr/local/etc/coltan/interfaces.json'

async function ensureDir() {
  await execAsync('mkdir -p /usr/local/etc/coltan')
}

async function getAssignments() {
  try {
    await ensureDir()
    const content = await fs.readFile(IFACES_FILE, 'utf8')
    return JSON.parse(content)
  } catch(e) { return {} }
}

async function saveAssignments(assignments) {
  await ensureDir()
  await fs.writeFile(IFACES_FILE, JSON.stringify(assignments, null, 2))
}

async function getPhysicalInterfaces() {
  try {
    const { stdout } = await execAsync('ifconfig')
    const interfaces = []
    const blocks = stdout.split(/^(?=\S)/m)
    for (const block of blocks) {
      if (!block.trim()) continue
      const nameMatch = block.match(/^(\S+):/)
      if (!nameMatch) continue
      const name = nameMatch[1]
      if (name === 'lo0') continue
      const statusMatch = block.match(/status: (\S+)/)
      const status = statusMatch ? statusMatch[1] : 'unknown'
      const ipv4Match = block.match(/inet (\d+\.\d+\.\d+\.\d+)/)
      const ip = ipv4Match ? ipv4Match[1] : null
      const netmaskMatch = block.match(/netmask (0x[0-9a-f]+)/)
      let netmask = '255.255.255.0'
      if (netmaskMatch) {
        const hex = parseInt(netmaskMatch[1], 16)
        netmask = [(hex>>24)&255,(hex>>16)&255,(hex>>8)&255,hex&255].join('.')
      }
      const macMatch = block.match(/ether ([\da-f:]+)/)
      const mac = macMatch ? macMatch[1] : null
      const mediaMatch = block.match(/media: (.+)/)
      const media = mediaMatch ? mediaMatch[1].split('\n')[0].trim() : null
      interfaces.push({ name, status, ip, netmask, mac, media })
    }
    return interfaces
  } catch(e) { return [] }
}

async function getInterfacesWithRoles() {
  const [physical, assignments] = await Promise.all([
    getPhysicalInterfaces(),
    getAssignments()
  ])
  return physical.map(iface => ({
    ...iface,
    role: assignments[iface.name]?.role || 'unassigned',
    description: assignments[iface.name]?.description || ''
  }))
}

async function setInterfaceRole(name, role, description) {
  // Enable IP forwarding when assigning LAN/OPT role
  if (role === 'LAN' || role === 'OPT') {
    try { await execAsync('sysctl net.inet.ip.forwarding=1 2>/dev/null') } catch(e) {}
  }
  const assignments = await getAssignments()
  assignments[name] = { role, description: description || '' }
  await saveAssignments(assignments)
  return { success: true }
}

async function setInterfaceIP(name, ip, netmask, gateway) {
  try {
    await execAsync(`sysrc ifconfig_${name}="inet ${ip} netmask ${netmask}"`)
    if (gateway) await execAsync(`sysrc defaultrouter="${gateway}"`)
    // Apply IP change on the fly WITHOUT restarting the whole network
    try { await execAsync(`ifconfig ${name} inet ${ip} netmask ${netmask}`) } catch(e) {}
    // Regenerate firewall with new IPs
    try {
      const { generateAndReload } = require('./firewall.service')
      await generateAndReload()
    } catch(e) {}
    return { success: true }
  } catch(e) { return { success: false, error: e.message } }
}

async function setInterfaceDHCP(name) {
  try {
    // Cambiar rc.conf para que esta interfaz use DHCP en vez de IP estatica
    await execAsync(`sysrc ifconfig_${name}="DHCP"`)

    // Si esta interfaz era la que definia el defaultrouter estatico, lo quitamos
    // (dhclient va a configurar su propio gateway automaticamente)
    try {
      const { stdout } = await execAsync('sysrc -n defaultrouter 2>/dev/null')
      if (stdout.trim()) {
        await execAsync('sysrc -x defaultrouter 2>/dev/null || true')
      }
    } catch(e) {}

    // Bajar la interfaz y levantarla para que tome DHCP inmediatamente sin reboot
    try { await execAsync(`ifconfig ${name} down`) } catch(e) {}
    await new Promise(r => setTimeout(r, 500))
    try { await execAsync(`ifconfig ${name} up`) } catch(e) {}
    // Disparar dhclient para obtener IP ahora mismo (no esperar al proximo boot)
    try { await execAsync(`dhclient ${name} 2>&1 &`) } catch(e) {}

    // Regenerar firewall (la IP puede tardar unos segundos en asignarse via DHCP)
    setTimeout(async () => {
      try {
        const { generateAndReload } = require('./firewall.service')
        await generateAndReload()
      } catch(e) {}
    }, 5000)

    return { success: true, message: 'Interfaz configurada por DHCP. Puede tardar unos segundos en obtener IP.' }
  } catch(e) { return { success: false, error: e.message } }
}

module.exports = {
  getInterfacesWithRoles, setInterfaceRole,
  setInterfaceIP, setInterfaceDHCP, getPhysicalInterfaces, getAssignments
}
