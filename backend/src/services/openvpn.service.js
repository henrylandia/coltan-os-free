'use strict'

const { exec } = require('child_process')
const { promisify } = require('util')
const execAsync = promisify(exec)
const fs = require('fs').promises
const path = require('path')

const OVPN_DIR = '/usr/local/etc/openvpn'
const PKI_DIR = `${OVPN_DIR}/easy-rsa/pki`
const SERVERS_FILE = '/usr/local/etc/coltan/ovpn-servers.json'
const CLIENTS_FILE = '/usr/local/etc/coltan/ovpn-clients.json'

async function ensureDir() {
  await execAsync('mkdir -p /usr/local/etc/coltan')
  await execAsync(`mkdir -p ${OVPN_DIR}/servers`)
  await execAsync(`mkdir -p ${OVPN_DIR}/ccd`)
  await execAsync('mkdir -p /var/log/openvpn')
}

// ─── PKI ──────────────────────────────────────────────────────────────────────

async function getCertificates() {
  try {
    const indexFile = `${PKI_DIR}/index.txt`
    const content = await fs.readFile(indexFile, 'utf8')
    const certs = []
    for (const line of content.trim().split('\n')) {
      if (!line.trim()) continue
      const parts = line.split('\t')
      const status = parts[0] === 'V' ? 'valid' : parts[0] === 'R' ? 'revoked' : 'expired'
      const expiry = parts[1]
      const cn = parts[5]?.match(/CN=([^/]+)/)?.[1] || parts[5]
      const serial = parts[3]
      const type = cn === 'server' ? 'server' : cn?.includes('CA') ? 'ca' : 'client'
      certs.push({ cn, status, expiry, serial, type })
    }
    return certs
  } catch(e) { return [] }
}

async function getCAInfo() {
  try {
    const { stdout } = await execAsync(`openssl x509 -in ${PKI_DIR}/ca.crt -noout -dates -subject 2>/dev/null`)
    return stdout.trim()
  } catch(e) { return 'N/A' }
}

async function downloadCert(name, type) {
  const paths = {
    ca: `${PKI_DIR}/ca.crt`,
    cert: `${PKI_DIR}/issued/${name}.crt`,
    key: `${PKI_DIR}/private/${name}.key`,
    ta: `${PKI_DIR}/ta.key`,
    dh: `${PKI_DIR}/dh.pem`
  }
  try {
    return await fs.readFile(paths[type], 'utf8')
  } catch(e) { return null }
}

async function createClientCert(name) {
  const safeName = name.replace(/[^a-zA-Z0-9_-]/g, '_')
  await execAsync(`cd ${OVPN_DIR}/easy-rsa && easyrsa --batch build-client-full ${safeName} nopass`)
  return safeName
}

async function revokeCert(name) {
  await execAsync(`cd ${OVPN_DIR}/easy-rsa && easyrsa --batch revoke ${name}`)
  await execAsync(`cd ${OVPN_DIR}/easy-rsa && easyrsa gen-crl`)
  // Copy CRL to openvpn dir
  await execAsync(`cp ${PKI_DIR}/crl.pem ${OVPN_DIR}/crl.pem`)
}

// ─── SERVERS ──────────────────────────────────────────────────────────────────

async function getServers() {
  try {
    const content = await fs.readFile(SERVERS_FILE, 'utf8')
    return JSON.parse(content)
  } catch(e) {
    // Return default server if exists
    try {
      await fs.access(`${OVPN_DIR}/server.conf`)
      return [{
        id: 'default',
        name: 'Default Server',
        port: 1194,
        proto: 'udp',
        network: '10.8.0.0',
        netmask: '255.255.255.0',
        type: 'remote-access',
        interface: 'tun0',
        enabled: true,
        createdAt: new Date().toISOString()
      }]
    } catch(e2) { return [] }
  }
}

async function saveServers(servers) {
  await ensureDir()
  await fs.writeFile(SERVERS_FILE, JSON.stringify(servers, null, 2))
}

async function addServer(server) {
  await ensureDir()
  const servers = await getServers()
  const id = Date.now().toString()
  const tunNum = servers.length
  const newServer = {
    id,
    name: server.name,
    port: parseInt(server.port) || 1194,
    proto: server.proto || 'udp',
    network: server.network || '10.8.0.0',
    netmask: server.netmask || '255.255.255.0',
    type: server.type || 'remote-access',
    interface: `tun${tunNum}`,
    dns1: server.dns1 || '8.8.8.8',
    dns2: server.dns2 || '1.1.1.1',
    siteNetwork: server.siteNetwork || '',
    siteMask: server.siteMask || '',
    enabled: true,
    createdAt: new Date().toISOString()
  }
  servers.push(newServer)
  await saveServers(servers)
  await generateServerConf(newServer)
  await startServer(id)
  return { success: true, server: newServer }
}

async function deleteServer(id) {
  const servers = await getServers()
  const server = servers.find(s => s.id === id)
  if (!server) return { success: false, error: 'Server not found' }
  await stopServer(id)
  try { await fs.unlink(`${OVPN_DIR}/servers/${id}.conf`) } catch(e) {}
  const filtered = servers.filter(s => s.id !== id)
  await saveServers(filtered)
  return { success: true }
}

async function generateServerConf(server) {
  const conf = `port ${server.port}
proto ${server.proto}
dev ${server.interface}

ca ${PKI_DIR}/ca.crt
cert ${PKI_DIR}/issued/server.crt
key ${PKI_DIR}/private/server.key
dh ${PKI_DIR}/dh.pem
tls-auth ${PKI_DIR}/ta.key 0

server ${server.network} ${server.netmask}
ifconfig-pool-persist /var/log/openvpn/ipp-${server.id}.txt
client-config-dir ${OVPN_DIR}/ccd

${server.type === 'site-to-site' && server.siteNetwork ? `route ${server.siteNetwork} ${server.siteMask || '255.255.255.0'}` : ''}

push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS ${server.dns1 || '8.8.8.8'}"
${server.dns2 ? `push "dhcp-option DNS ${server.dns2}"` : ''}

keepalive 10 120
cipher AES-256-GCM
tls-version-min 1.2
user nobody
group nobody
persist-key
persist-tun

status /var/log/openvpn/status-${server.id}.log
log /var/log/openvpn/openvpn-${server.id}.log
verb 3
`
  await fs.writeFile(`${OVPN_DIR}/servers/${server.id}.conf`, conf)

  // Add PF rule for this port
  try {
    await execAsync(`pfctl -sr 2>/dev/null | grep -q "port = ${server.port}" || echo "pass in proto ${server.proto} to port ${server.port} keep state" | pfctl -a coltan/ovpn-${server.id} -f - 2>/dev/null`)
  } catch(e) {}
}

async function startServer(id) {
  try {
    const servers = await getServers()
    const server = servers.find(s => s.id === id)
    if (!server) return { success: false, error: 'Server not found' }

    const confFile = id === 'default'
      ? `${OVPN_DIR}/server.conf`
      : `${OVPN_DIR}/servers/${id}.conf`

    // Kill any existing process on same interface
    try { await execAsync(`pkill -f "${server.interface}" 2>/dev/null`) } catch(e) {}
    await new Promise(r => setTimeout(r, 500))

    // Clean up old routes
    try { await execAsync(`ifconfig ${server.interface} destroy 2>/dev/null`) } catch(e) {}

    // Start daemon
    await execAsync(`openvpn --daemon ovpn-${id} --config ${confFile}`)

    // Mark as enabled in servers list
    server.autostart = true
    await saveServers(servers)

    // Add to rc.local for persistence
    await persistServer(id, confFile, true)

    return { success: true }
  } catch(e) { return { success: false, error: e.message } }
}

async function persistServer(id, confFile, enable) {
  try {
    const persistFile = '/usr/local/etc/coltan/ovpn-autostart.json'
    let autostart = {}
    try {
      autostart = JSON.parse(await fs.readFile(persistFile, 'utf8'))
    } catch(e) {}

    if (enable) {
      autostart[id] = confFile
    } else {
      delete autostart[id]
    }

    await fs.writeFile(persistFile, JSON.stringify(autostart, null, 2))

    // Generate rc script
    const rcScript = Object.entries(autostart).map(([sid, conf]) =>
      `openvpn --daemon ovpn-${sid} --config ${conf}`
    ).join('\n')

    await fs.writeFile('/usr/local/etc/coltan/openvpn-start.sh',
      `#!/bin/sh\n# Coltan OS — OpenVPN autostart\nsleep 5\n${rcScript}\n`)
    await execAsync('chmod +x /usr/local/etc/coltan/openvpn-start.sh')

    // Add to rc.local
    let rcLocal = ''
    try { rcLocal = await fs.readFile('/etc/rc.local', 'utf8') } catch(e) {}
    if (!rcLocal.includes('openvpn-start.sh')) {
      await fs.appendFile('/etc/rc.local',
        '\n/usr/local/etc/coltan/openvpn-start.sh &\n')
      await execAsync('chmod +x /etc/rc.local')
    }
  } catch(e) { console.error('persistServer error:', e.message) }
}

async function stopServer(id) {
  try {
    const servers = await getServers()
    const server = servers.find(s => s.id === id)
    if (server) {
      await execAsync(`pkill -f "ovpn-${id}" 2>/dev/null || true`)
      await execAsync(`pkill -f "${server.interface}" 2>/dev/null || true`)
      try { await execAsync(`ifconfig ${server.interface} destroy 2>/dev/null`) } catch(e) {}
      server.autostart = false
      await saveServers(servers)
      await persistServer(id, null, false)
    }
    return { success: true }
  } catch(e) { return { success: false, error: e.message } }
}

async function getServerStatus(id) {
  try {
    const logFile = id === 'default'
      ? '/var/log/openvpn/status.log'
      : `/var/log/openvpn/status-${id}.log`

    const servers = await getServers()
    const server = servers.find(s => s.id === id)
    if (!server) return { running: false, clients: [] }

    // Check if process is running
    let running = false
    try {
      const { stdout: ps } = await execAsync(`pgrep -f "ovpn-${id}" 2>/dev/null`)
      running = ps.trim().length > 0
    } catch(e) {
      try {
        const { stdout: ps2 } = await execAsync(`pgrep -f "${server.interface}" 2>/dev/null`)
        running = ps2.trim().length > 0
      } catch(e2) { running = false }
    }

    // Parse status log
    let clients = []
    try {
      const status = await fs.readFile(logFile, 'utf8')
      const lines = status.split('\n')
      let inClient = false
      for (const line of lines) {
        if (line.startsWith('Common Name')) { inClient = true; continue }
        if (line.startsWith('ROUTING TABLE') || line.startsWith('GLOBAL')) break
        if (inClient && line.trim() && !line.startsWith('Common Name')) {
          const parts = line.split(',')
          if (parts.length >= 4 && parts[0] !== 'Common Name') {
            clients.push({
              name: parts[0],
              endpoint: parts[1],
              rxBytes: parts[2],
              txBytes: parts[3],
              connectedSince: parts[4]?.trim()
            })
          }
        }
      }
    } catch(e) {}

    return { running, clients, connectedClients: clients.length }
  } catch(e) { return { running: false, clients: [] } }
}

// ─── CLIENTS ──────────────────────────────────────────────────────────────────

async function getClients() {
  try {
    const content = await fs.readFile(CLIENTS_FILE, 'utf8')
    return JSON.parse(content)
  } catch(e) { return [] }
}

async function saveClients(clients) {
  await fs.writeFile(CLIENTS_FILE, JSON.stringify(clients, null, 2))
}

async function addClient(name, serverId) {
  await ensureDir()
  const safeName = name.replace(/[^a-zA-Z0-9_-]/g, '_')

  try {
    await createClientCert(safeName)
  } catch(e) {
    if (!e.message.includes('already exists')) throw e
  }

  const clients = await getClients()
  const client = {
    id: Date.now().toString(),
    name,
    safeName,
    serverId: serverId || 'default',
    enabled: true,
    createdAt: new Date().toISOString()
  }
  clients.push(client)
  await saveClients(clients)
  return { success: true, client }
}

async function deleteClient(id) {
  const clients = await getClients()
  const client = clients.find(c => c.id === id)
  if (!client) return { success: false, error: 'Client not found' }

  try { await revokeCert(client.safeName) } catch(e) {}

  const filtered = clients.filter(c => c.id !== id)
  await saveClients(filtered)
  return { success: true }
}

async function getClientOVPN(id, serverPublicIP) {
  const clients = await getClients()
  const client = clients.find(c => c.id === id)
  if (!client) return null

  const servers = await getServers()
  const server = servers.find(s => s.id === client.serverId) || servers[0]
  if (!server) return null

  const ca = await fs.readFile(`${PKI_DIR}/ca.crt`, 'utf8')
  const cert = await fs.readFile(`${PKI_DIR}/issued/${client.safeName}.crt`, 'utf8')
  const key = await fs.readFile(`${PKI_DIR}/private/${client.safeName}.key`, 'utf8')
  const ta = await fs.readFile(`${PKI_DIR}/ta.key`, 'utf8')

  const certMatch = cert.match(/-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----/)
  const certOnly = certMatch ? certMatch[0] : cert

  return `# Coltan OS — OpenVPN Client Config
# Client: ${client.name}
# Server: ${server.name}
# Generated: ${new Date().toISOString()}

client
dev tun
proto ${server.proto}
remote ${serverPublicIP} ${server.port}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
tls-version-min 1.2
verb 3

<ca>
${ca.trim()}
</ca>

<cert>
${certOnly.trim()}
</cert>

<key>
${key.trim()}
</key>

<tls-auth>
${ta.trim()}
</tls-auth>
key-direction 1
`
}

// ─── GLOBAL STATUS ────────────────────────────────────────────────────────────

async function getAllStatus() {
  const servers = await getServers()
  const statuses = await Promise.all(servers.map(async s => {
    const status = await getServerStatus(s.id)
    return { ...s, ...status }
  }))
  return statuses
}

module.exports = {
  getCertificates, getCAInfo, downloadCert, revokeCert, createClientCert,
  getServers, addServer, deleteServer, startServer, stopServer, getServerStatus, getAllStatus,
  getClients, addClient, deleteClient, getClientOVPN
}
