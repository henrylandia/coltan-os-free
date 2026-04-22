'use strict'

const { exec } = require('child_process')
const { promisify } = require('util')
const execAsync = promisify(exec)
const fs = require('fs').promises

const KEA_CONF = '/usr/local/etc/kea/kea-dhcp4.conf'
const LEASES_FILE = '/var/db/kea/dhcp4.leases'

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

async function getStatus() {
  try {
    const { stdout } = await execAsync('service kea status')
    return { running: stdout.includes('active') }
  } catch(e) { return { running: false } }
}

async function getSubnets() {
  const config = await getConfig()
  return config.Dhcp4.subnet4 || []
}

async function addSubnet(subnet) {
  const config = await getConfig()
  const id = Math.floor(Math.random() * 4000000) + 1
  const entry = {
    id,
    subnet: subnet.subnet,
    pools: [{ pool: `${subnet.poolStart} - ${subnet.poolEnd}` }],
    'option-data': [
      { name: 'routers', data: subnet.gateway },
      { name: 'domain-name-servers', data: subnet.dns || '8.8.8.8, 1.1.1.1' },
      { name: 'domain-name', data: subnet.domain || 'local' }
    ],
    'valid-lifetime': parseInt(subnet.leaseTime) || 86400,
    reservations: []
  }

  // Add interface
  const ifaces = config.Dhcp4['interfaces-config'].interfaces
  if (subnet.interface && !ifaces.includes(subnet.interface)) {
    ifaces.push(subnet.interface)
  }

  config.Dhcp4.subnet4.push(entry)
  await saveConfig(config)
  await restartKea()
  return { success: true, id }
}

async function deleteSubnet(id) {
  const config = await getConfig()
  config.Dhcp4.subnet4 = config.Dhcp4.subnet4.filter(s => s.id !== parseInt(id))
  await saveConfig(config)
  await restartKea()
  return { success: true }
}

async function addReservation(subnetId, reservation) {
  const config = await getConfig()
  const subnet = config.Dhcp4.subnet4.find(s => s.id === parseInt(subnetId))
  if (!subnet) return { success: false, error: 'Subnet not found' }
  if (!subnet.reservations) subnet.reservations = []
  subnet.reservations.push({
    'hw-address': reservation.mac,
    'ip-address': reservation.ip,
    hostname: reservation.hostname || ''
  })
  await saveConfig(config)
  await restartKea()
  return { success: true }
}

async function deleteReservation(subnetId, mac) {
  const config = await getConfig()
  const subnet = config.Dhcp4.subnet4.find(s => s.id === parseInt(subnetId))
  if (!subnet) return { success: false, error: 'Subnet not found' }
  subnet.reservations = (subnet.reservations || []).filter(r => r['hw-address'] !== mac)
  await saveConfig(config)
  await restartKea()
  return { success: true }
}

async function getLeases() {
  try {
    let content = ''
    const files = [
      '/var/db/kea/dhcp4.leases.2',
      '/var/db/kea/dhcp4.leases.1', 
      '/var/db/kea/dhcp4.leases'
    ]
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
    }).filter(l => l.address && parseInt(l['valid-lft'] || l.valid_lifetime) > 0)
  } catch(e) { return [] }
}

async function restartKea() {
  try {
    await execAsync('service kea restart 2>/dev/null || service kea start 2>/dev/null')
    return { success: true }
  } catch(e) { return { success: false, error: e.message } }
}

async function startKea() {
  try {
    await execAsync('service kea start')
    return { success: true }
  } catch(e) { return { success: false, error: e.message } }
}

async function stopKea() {
  try {
    await execAsync('service kea stop')
    return { success: true }
  } catch(e) { return { success: false, error: e.message } }
}

module.exports = {
  getStatus, getSubnets, addSubnet, deleteSubnet,
  addReservation, deleteReservation, getLeases,
  startKea, stopKea, restartKea
}
