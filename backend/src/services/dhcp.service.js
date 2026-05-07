'use strict'

const { exec } = require('child_process')
const { promisify } = require('util')
const execAsync = promisify(exec)
const fs = require('fs').promises

const KEA_CONF = '/usr/local/etc/kea/kea-dhcp4.conf'
const LEASES_FILE = '/var/db/kea/dhcp4.leases'

async function getStatus() {
  try {
    const { stdout } = await execAsync('service kea status 2>/dev/null')
    return { running: stdout.includes('DHCPv4 server: active') }
  } catch(e) { return { running: false } }
}

async function getConfig() {
  try {
    const content = await fs.readFile(KEA_CONF, 'utf8')
    return JSON.parse(content)
  } catch(e) {
    return { Dhcp4: { 'interfaces-config': { interfaces: [] }, 'lease-database': { type: 'memfile', persist: true, name: LEASES_FILE }, subnet4: [], 'option-data': [] } }
  }
}

async function saveConfig(config) {
  await fs.writeFile(KEA_CONF, JSON.stringify(config, null, 2))
}

async function getSubnets() {
  const config = await getConfig()
  return config.Dhcp4.subnet4 || []
}

async function addSubnet(data) {
  const config = await getConfig()
  const subnets = config.Dhcp4.subnet4 || []

  // Check duplicate by subnet prefix OR by interface
  const ifaceBase = data.subnet.split('.').slice(0,3).join('.')
  const duplicate = subnets.find(s => {
    const sBase = s.subnet.split('.').slice(0,3).join('.')
    return s.subnet === data.subnet || sBase === ifaceBase
  })
  if (duplicate) {
    // Remove duplicate and recreate — user wants to reconfigure
    config.Dhcp4.subnet4 = subnets.filter(s => s.id !== duplicate.id)
  }

  // Use provided DNS or fall back to interface IP
  let dnsServer = data.dns || data.gateway || '8.8.8.8'

  const newId = Math.floor(Math.random() * 4000000) + 1
  const subnet = {
    id: newId,
    subnet: data.subnet,
    interface: data.interface,
    pools: [{ pool: `${data.poolStart} - ${data.poolEnd}` }],
    'option-data': [
      { name: 'routers', data: data.gateway },
      { name: 'domain-name-servers', data: dnsServer },
      { name: 'domain-name', data: 'local' }
    ],
    'valid-lifetime': parseInt(data.leaseTime) || 86400,
    reservations: []
  }

  // Update interface list
  if (!config.Dhcp4['interfaces-config'].interfaces.includes(data.interface)) {
    config.Dhcp4['interfaces-config'].interfaces.push(data.interface)
  }

  config.Dhcp4.subnet4.push(subnet)
  await saveConfig(config)
  restartKea() // non-blocking
  return { success: true, subnet }
}

async function deleteSubnet(id) {
  const config = await getConfig()
  config.Dhcp4.subnet4 = (config.Dhcp4.subnet4 || []).filter(s => s.id !== parseInt(id))
  // Clean up interfaces if no subnets left
  if (config.Dhcp4.subnet4.length === 0) {
    config.Dhcp4['interfaces-config'].interfaces = []
  }
  await saveConfig(config)
  restartKea() // non-blocking
  return { success: true }
}

async function addReservation(subnetId, mac, ip, hostname) {
  const config = await getConfig()
  const subnet = config.Dhcp4.subnet4.find(s => s.id === parseInt(subnetId))
  if (!subnet) return { success: false, error: 'Subnet not found' }
  if (!subnet.reservations) subnet.reservations = []
  // Check duplicate MAC
  if (subnet.reservations.find(r => r['hw-address'] === mac)) {
    return { success: false, error: 'MAC address already has a reservation' }
  }
  subnet.reservations.push({ 'hw-address': mac, 'ip-address': ip, hostname: hostname || '' })
  await saveConfig(config)
  restartKea() // non-blocking
  return { success: true }
}

async function deleteReservation(subnetId, mac) {
  const config = await getConfig()
  const subnet = config.Dhcp4.subnet4.find(s => s.id === parseInt(subnetId))
  if (!subnet) return { success: false, error: 'Subnet not found' }
  subnet.reservations = (subnet.reservations || []).filter(r => r['hw-address'] !== mac)
  await saveConfig(config)
  restartKea() // non-blocking
  return { success: true }
}

async function getLeases() {
  try {
    const files = ['/var/db/kea/dhcp4.leases.2', '/var/db/kea/dhcp4.leases.1', '/var/db/kea/dhcp4.leases']
    let content = ''
    for (const f of files) {
      try {
        const c = await fs.readFile(f, 'utf8')
        const rows = c.trim().split('\n').filter(l => l && !l.startsWith('#') && !l.startsWith('address'))
        if (rows.length > 0) { content = c; break }
      } catch(e) {}
    }
    if (!content) return []
    const lines = content.trim().split('\n').filter(l => l && !l.startsWith('#'))
    if (lines.length < 2) return []
    const headers = lines[0].split(',')
    return lines.slice(1).map(line => {
      const values = line.split(',')
      const obj = {}
      headers.forEach((h, i) => obj[h.trim()] = values[i]?.trim())
      return obj
    }).filter(l => l.address)
  } catch(e) { return [] }
}

async function startKea() {
  try { await execAsync('service kea start 2>/dev/null'); return { success: true } }
  catch(e) { return { success: false, error: e.message } }
}

async function stopKea() {
  try { await execAsync('service kea stop 2>/dev/null'); return { success: true } }
  catch(e) { return { success: false, error: e.message } }
}

async function restartKea() {
  try { await execAsync('service kea restart 2>/dev/null') } catch(e) {}
}

module.exports = { getStatus, getConfig, saveConfig, getSubnets, addSubnet, deleteSubnet, addReservation, deleteReservation, getLeases, startKea, stopKea, restartKea }
