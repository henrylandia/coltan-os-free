'use strict'

const { exec } = require('child_process')
const { promisify } = require('util')
const execAsync = promisify(exec)
const fs = require('fs').promises

const IFACES_FILE = '/usr/local/etc/coltan/interfaces.json'
const WAN_DNS_FILE = '/usr/local/etc/coltan/wan-dns.json'

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
    // Guardar el gateway y la IP estatica anteriores por si hay que revertir (rollback de seguridad)
    let previousGateway = ''
    try {
      const { stdout } = await execAsync('sysrc -n defaultrouter 2>/dev/null')
      previousGateway = stdout.trim()
    } catch(e) {}

    let previousIP = ''
    let previousNetmask = ''
    try {
      const { stdout: ifcfgBefore } = await execAsync(`ifconfig ${name}`)
      const m = ifcfgBefore.match(/inet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-f]+)/)
      if (m) {
        previousIP = m[1]
        const hex = parseInt(m[2], 16)
        previousNetmask = [(hex>>24)&255,(hex>>16)&255,(hex>>8)&255,hex&255].join('.')
      }
    } catch(e) {}

    // Cambiar rc.conf para que esta interfaz use DHCP en vez de IP estatica
    await execAsync(`sysrc ifconfig_${name}="DHCP"`)

    // IMPORTANTE: borrar explicitamente la IP estatica actual antes de pedir DHCP.
    // ifconfig down/up NO elimina una IP asignada manualmente, lo que causaba
    // falsos positivos al verificar si el DHCP realmente funciono.
    if (previousIP) {
      try { await execAsync(`ifconfig ${name} inet ${previousIP} delete`) } catch(e) {}
    }

    try { await execAsync(`ifconfig ${name} down`) } catch(e) {}
    await new Promise(r => setTimeout(r, 500))
    try { await execAsync(`ifconfig ${name} up`) } catch(e) {}

    // Pedir IP por DHCP y ESPERAR el resultado real (con timeout) antes de decidir
    let dhcpOk = false
    try {
      await execAsync(`timeout 15 dhclient ${name} 2>&1`)
      const { stdout: ifcfg } = await execAsync(`ifconfig ${name}`)
      dhcpOk = /inet \d+\.\d+\.\d+\.\d+/.test(ifcfg)
    } catch(e) { dhcpOk = false }

    if (!dhcpOk) {
      // ROLLBACK COMPLETO: restaurar IP estatica y gateway anteriores para no dejar el equipo sin salida
      try { await execAsync(`sysrc ifconfig_${name}="inet ${previousIP} netmask ${previousNetmask}"`) } catch(e) {}
      if (previousIP && previousNetmask) {
        try { await execAsync(`ifconfig ${name} inet ${previousIP} netmask ${previousNetmask}`) } catch(e) {}
      }
      if (previousGateway) {
        try { await execAsync(`sysrc defaultrouter="${previousGateway}"`) } catch(e) {}
        try { await execAsync(`route add default ${previousGateway} 2>/dev/null`) } catch(e) {}
      }
      return { success: false, error: 'No se pudo obtener IP por DHCP en esta interfaz. Se restauro la configuracion anterior (' + previousIP + '). Verifica que haya un servidor DHCP disponible en esa red.' }
    }

    // DHCP funciono de verdad: ahora si limpiamos el defaultrouter estatico
    if (previousGateway) {
      try { await execAsync('sysrc -x defaultrouter 2>/dev/null || true') } catch(e) {}
    }

    // Regenerar firewall con la nueva IP
    try {
      const { generateAndReload } = require('./firewall.service')
      await generateAndReload()
    } catch(e) {}

    return { success: true, message: 'Interfaz configurada por DHCP correctamente.' }
  } catch(e) { return { success: false, error: e.message } }
}

// ── DNS especifico de WAN (separado del DNS que Kea entrega a la LAN) ──────

async function getWanDNS() {
  try {
    const content = await fs.readFile(WAN_DNS_FILE, 'utf8')
    return JSON.parse(content)
  } catch(e) {
    return { mode: 'auto', servers: [] }
  }
}

async function setWanDNS(mode, servers) {
  try {
    await ensureDir()
    const config = {
      mode: mode === 'manual' ? 'manual' : 'auto',
      servers: mode === 'manual' ? (servers || []).filter(Boolean) : []
    }
    await fs.writeFile(WAN_DNS_FILE, JSON.stringify(config, null, 2))

    if (config.mode === 'manual' && config.servers.length > 0) {
      const content = config.servers.map(s => `nameserver ${s}`).join('\n') + '\n'
      await fs.writeFile('/etc/resolv.conf', content)
    } else {
      // Modo automatico: si la WAN es estatica usamos DNS publicos por defecto.
      // Si la WAN es DHCP, dejamos que dhclient mantenga el resolv.conf entregado por el ISP.
      const roles = await getAssignments()
      const wanIface = Object.entries(roles).find(([, v]) => v.role === 'WAN')?.[0]
      let wanMode = ''
      if (wanIface) {
        try {
          const { stdout } = await execAsync(`sysrc -n ifconfig_${wanIface} 2>/dev/null`)
          wanMode = stdout.trim()
        } catch(e) {}
      }
      if (wanMode !== 'DHCP') {
        await fs.writeFile('/etc/resolv.conf', 'nameserver 8.8.8.8\nnameserver 1.1.1.1\n')
      }
    }
    return { success: true }
  } catch(e) { return { success: false, error: e.message } }
}

module.exports = {
  getInterfacesWithRoles, setInterfaceRole,
  setInterfaceIP, setInterfaceDHCP, getPhysicalInterfaces, getAssignments,
  getWanDNS, setWanDNS
}
