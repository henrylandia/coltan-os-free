'use strict'

const { exec } = require('child_process')
const { promisify } = require('util')
const execAsync = promisify(exec)
const fs = require('fs').promises

const VLANS_FILE = '/usr/local/etc/coltan/vlans.json'

async function ensureDir() {
  await execAsync('mkdir -p /usr/local/etc/coltan')
}

// ─── CRUD ─────────────────────────────────────────────────────────────────────

async function getVLANs() {
  try {
    const content = await fs.readFile(VLANS_FILE, 'utf8')
    return JSON.parse(content)
  } catch(e) { return [] }
}

async function saveVLANs(vlans) {
  await ensureDir()
  await fs.writeFile(VLANS_FILE, JSON.stringify(vlans, null, 2))
}

async function createVLAN({ tag, parent, ip, netmask, description }) {
  if (!tag || !parent) return { success: false, error: 'tag y parent requeridos' }
  if (tag < 1 || tag > 4094) return { success: false, error: 'VLAN tag debe ser entre 1 y 4094' }

  const vlans = await getVLANs()
  if (vlans.find(v => v.tag === parseInt(tag) && v.parent === parent)) {
    return { success: false, error: `VLAN ${tag} ya existe en ${parent}` }
  }

  const name = `vlan${tag}`
  const vlan = {
    id: Date.now().toString(),
    name,
    tag: parseInt(tag),
    parent,
    ip: ip || null,
    netmask: netmask || '255.255.255.0',
    description: description || '',
    createdAt: new Date().toISOString()
  }

  // Create VLAN interface in FreeBSD
  try {
    await execAsync(`ifconfig ${name} create vlan ${tag} vlandev ${parent} 2>/dev/null || true`)
    if (ip) {
      await execAsync(`ifconfig ${name} inet ${ip} netmask ${netmask || '255.255.255.0'} 2>/dev/null`)
    }
    await execAsync(`ifconfig ${name} up 2>/dev/null`)
  } catch(e) {
    return { success: false, error: `Error creando interfaz VLAN: ${e.message}` }
  }

  // Persist in rc.conf
  await execAsync(`sysrc ifconfig_${name}="vlan ${tag} vlandev ${parent}" 2>/dev/null`)
  if (ip) {
    await execAsync(`sysrc ifconfig_${name}_ip="inet ${ip} netmask ${netmask || '255.255.255.0'}" 2>/dev/null`)
    // Apply IP
    await execAsync(`ifconfig ${name} inet ${ip} netmask ${netmask || '255.255.255.0'} 2>/dev/null || true`)
  }

  // Add to interfaces.json with LAN role
  try {
    const ifacesContent = await fs.readFile('/usr/local/etc/coltan/interfaces.json', 'utf8')
    const ifaces = JSON.parse(ifacesContent)
    ifaces[name] = { role: 'LAN', description: description || `VLAN ${tag}`, vlan: true, tag, parent }
    await fs.writeFile('/usr/local/etc/coltan/interfaces.json', JSON.stringify(ifaces, null, 2))
  } catch(e) {}

  // Regenerate PF
  try {
    const { generateAndReload } = require('./firewall.service')
    await generateAndReload()
  } catch(e) {}

  vlans.push(vlan)
  await saveVLANs(vlans)
  return { success: true, vlan }
}

async function deleteVLAN(id) {
  const vlans = await getVLANs()
  const vlan = vlans.find(v => v.id === id)
  if (!vlan) return { success: false, error: 'VLAN no encontrada' }

  // Destroy VLAN interface
  try {
    await execAsync(`ifconfig ${vlan.name} destroy 2>/dev/null || true`)
  } catch(e) {}

  // Remove from rc.conf
  try {
    await execAsync(`sysrc -x ifconfig_${vlan.name} 2>/dev/null || true`)
    await execAsync(`sysrc -x ifconfig_${vlan.name}_ip 2>/dev/null || true`)
  } catch(e) {}

  // Remove from interfaces.json
  try {
    const ifacesContent = await fs.readFile('/usr/local/etc/coltan/interfaces.json', 'utf8')
    const ifaces = JSON.parse(ifacesContent)
    delete ifaces[vlan.name]
    await fs.writeFile('/usr/local/etc/coltan/interfaces.json', JSON.stringify(ifaces, null, 2))
  } catch(e) {}

  // Regenerate PF
  try {
    const { generateAndReload } = require('./firewall.service')
    await generateAndReload()
  } catch(e) {}

  const filtered = vlans.filter(v => v.id !== id)
  await saveVLANs(filtered)
  return { success: true }
}

async function updateVLAN(id, { ip, netmask, description }) {
  const vlans = await getVLANs()
  const vlan = vlans.find(v => v.id === id)
  if (!vlan) return { success: false, error: 'VLAN no encontrada' }

  if (ip) {
    vlan.ip = ip
    vlan.netmask = netmask || vlan.netmask
    try {
      await execAsync(`ifconfig ${vlan.name} inet ${ip} netmask ${vlan.netmask} 2>/dev/null`)
      await execAsync(`sysrc ifconfig_${vlan.name}_ip="inet ${ip} netmask ${vlan.netmask}" 2>/dev/null`)
    } catch(e) {}
  }
  if (description !== undefined) vlan.description = description

  // Update interfaces.json
  try {
    const ifacesContent = await fs.readFile('/usr/local/etc/coltan/interfaces.json', 'utf8')
    const ifaces = JSON.parse(ifacesContent)
    if (ifaces[vlan.name]) {
      ifaces[vlan.name].description = vlan.description || `VLAN ${vlan.tag}`
    }
    await fs.writeFile('/usr/local/etc/coltan/interfaces.json', JSON.stringify(ifaces, null, 2))
  } catch(e) {}

  // Regenerate PF
  try {
    const { generateAndReload } = require('./firewall.service')
    await generateAndReload()
  } catch(e) {}

  await saveVLANs(vlans)
  return { success: true, vlan }
}

// ─── RESTORE ON BOOT ──────────────────────────────────────────────────────────
// Called from rc.local or server startup to restore VLANs after reboot

async function restoreVLANs() {
  const vlans = await getVLANs()
  for (const vlan of vlans) {
    try {
      await execAsync(`ifconfig ${vlan.name} create vlan ${vlan.tag} vlandev ${vlan.parent} 2>/dev/null || true`)
      if (vlan.ip) {
        await execAsync(`ifconfig ${vlan.name} inet ${vlan.ip} netmask ${vlan.netmask} 2>/dev/null || true`)
      }
      await execAsync(`ifconfig ${vlan.name} up 2>/dev/null || true`)
    } catch(e) {}
  }
  return { success: true, restored: vlans.length }
}

// ─── GET LAN INTERFACES (physical only, for VLAN parent selection) ────────────

async function getLANParents() {
  try {
    const { stdout } = await execAsync('ifconfig -l')
    const all = stdout.trim().split(/\s+/)
    // Return only physical interfaces (not VLANs, not lo)
    return all.filter(i => !i.startsWith('lo') && !i.startsWith('vlan') && !i.startsWith('wg') && !i.startsWith('tun'))
  } catch(e) { return [] }
}

module.exports = { getVLANs, createVLAN, deleteVLAN, updateVLAN, restoreVLANs, getLANParents }
