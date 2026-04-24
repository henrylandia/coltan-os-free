'use strict'

const { exec } = require('child_process')
const { promisify } = require('util')
const execAsync = promisify(exec)
const fs = require('fs').promises

const WG_DIR = '/usr/local/etc/wireguard'
const WG_CONF = `${WG_DIR}/wg0.conf`
const PEERS_FILE = '/usr/local/etc/coltan/wg-peers.json'

async function ensureDir() {
  await execAsync('mkdir -p /usr/local/etc/coltan')
}

async function getServerKeys() {
  try {
    const privateKey = (await fs.readFile(`${WG_DIR}/server_private.key`, 'utf8')).trim()
    const publicKey = (await fs.readFile(`${WG_DIR}/server_public.key`, 'utf8')).trim()
    return { privateKey, publicKey }
  } catch(e) { return { privateKey: '', publicKey: '' } }
}

async function getConfig() {
  try {
    const content = await fs.readFile('/usr/local/etc/coltan/wg-config.json', 'utf8')
    return JSON.parse(content)
  } catch(e) {
    return {
      listenPort: 51820,
      serverIP: '10.0.0.1/24',
      dns: '8.8.8.8',
      interface: 'wg0',
      allowedNetworks: '0.0.0.0/0',
      postUp: '',
      postDown: ''
    }
  }
}

async function saveConfig(config) {
  await execAsync('mkdir -p /usr/local/etc/coltan')
  await fs.writeFile('/usr/local/etc/coltan/wg-config.json', JSON.stringify(config, null, 2))
}

async function getPeers() {
  try {
    await ensureDir()
    const content = await fs.readFile(PEERS_FILE, 'utf8')
    return JSON.parse(content)
  } catch(e) { return [] }
}

async function savePeers(peers) {
  await ensureDir()
  await fs.writeFile(PEERS_FILE, JSON.stringify(peers, null, 2))
}

async function generatePeerKeys() {
  const { stdout: privateKey } = await execAsync('wg genkey')
  const { stdout: publicKey } = await execAsync(`echo "${privateKey.trim()}" | wg pubkey`)
  const { stdout: presharedKey } = await execAsync('wg genpsk')
  return {
    privateKey: privateKey.trim(),
    publicKey: publicKey.trim(),
    presharedKey: presharedKey.trim()
  }
}

async function addPeer(peer) {
  const peers = await getPeers()
  const keys = await generatePeerKeys()
  const config = await getConfig()

  // Calculate next available IP
  const usedIPs = peers.map(p => parseInt(p.allowedIP.split('.')[3]))
  let nextIP = 2
  while (usedIPs.includes(nextIP)) nextIP++
  const serverBase = config.serverIP.split('/')[0].split('.').slice(0, 3).join('.')

  const newPeer = {
    id: Date.now().toString(),
    name: peer.name,
    enabled: true,
    privateKey: keys.privateKey,
    publicKey: keys.publicKey,
    presharedKey: keys.presharedKey,
    allowedIP: `${serverBase}.${nextIP}/32`,
    createdAt: new Date().toISOString()
  }

  peers.push(newPeer)
  await savePeers(peers)
  await generateWGConf()
  await reloadWG()
  return { success: true, peer: newPeer }
}

async function deletePeer(id) {
  const peers = await getPeers()
  const filtered = peers.filter(p => p.id !== id)
  await savePeers(filtered)
  await generateWGConf()
  await reloadWG()
  return { success: true }
}

async function togglePeer(id) {
  const peers = await getPeers()
  const peer = peers.find(p => p.id === id)
  if (!peer) return { success: false, error: 'Peer not found' }
  peer.enabled = !peer.enabled
  await savePeers(peers)
  await generateWGConf()
  await reloadWG()
  return { success: true, enabled: peer.enabled }
}

async function generateWGConf() {
  const { privateKey } = await getServerKeys()
  const config = await getConfig()
  const peers = await getPeers()

  // Get WAN and LAN interfaces
  let wanIface = 're0'
  let lanIface = 're1'
  try {
    const ifaceContent = await fs.readFile('/usr/local/etc/coltan/interfaces.json', 'utf8')
    const ifaces = JSON.parse(ifaceContent)
    for (const [name, val] of Object.entries(ifaces)) {
      if (val.role === 'WAN') wanIface = name
      if (val.role === 'LAN') lanIface = name
    }
  } catch(e) {}

  // Get VPN network
  const serverAddr = config.serverIP ? config.serverIP.split('/')[0] : '10.0.0.1'
  const vpnNet = serverAddr.replace(/\.\d+$/, '.0/24')

  const postUp = config.postUp || [
    `sysctl net.inet.ip.forwarding=1`,
    `pfctl -f /etc/pf.conf 2>/dev/null`,
    `route delete -net ${vpnNet} 2>/dev/null; route add -net ${vpnNet} -interface wg0 2>/dev/null`
  ].join('; ')

  const postDown = config.postDown || [
    `route delete -net ${vpnNet} -interface wg0 2>/dev/null || true`
  ].join('; ')

  let conf = `[Interface]
Address = ${config.serverIP}
ListenPort = ${config.listenPort}
PrivateKey = ${privateKey}
PostUp = ${postUp}
PostDown = ${postDown}

`

  peers.filter(p => p.enabled).forEach(peer => {
    conf += `[Peer]
# ${peer.name}
PublicKey = ${peer.publicKey}
PresharedKey = ${peer.presharedKey}
AllowedIPs = ${peer.allowedIP}

`
  })

  await fs.writeFile(WG_CONF, conf)
  await execAsync(`chmod 600 ${WG_CONF}`)
  return conf
}

async function getPeerConfig(id, serverPublicIP) {
  const peers = await getPeers()
  const peer = peers.find(p => p.id === id)
  if (!peer) return null

  const config = await getConfig()
  const { publicKey: serverPubKey } = await getServerKeys()

  const allowedIPs = peer.allowedNetworks || config.allowedNetworks || '0.0.0.0/0'

  return `[Interface]
Address = ${peer.allowedIP.replace("/32", "/24")}
PrivateKey = ${peer.privateKey}
DNS = ${config.dns}

[Peer]
PublicKey = ${serverPubKey}
PresharedKey = ${peer.presharedKey}
Endpoint = ${serverPublicIP}:${config.listenPort}
AllowedIPs = ${allowedIPs}
PersistentKeepalive = 25
`
}

async function startWG() {
  try {
    const config = await getConfig()

    // Generate conf first
    await generateWGConf()

    // Down first to clean state
    try { await execAsync('wg-quick down wg0 2>/dev/null') } catch(e) {}
    await new Promise(r => setTimeout(r, 1000))

    // Up with full config
    await execAsync('wg-quick up wg0')

    // Get VPN network from config
    const serverIP = config.serverIP || '10.0.0.1/24'
    const vpnNet = serverIP.replace(/\.\d+\/\d+$/, '.0/24')
    const serverAddr = serverIP.split('/')[0]

    // Ensure ip forwarding
    await execAsync('sysctl net.inet.ip.forwarding=1')

    // Add pass rule for wg0 server IP specifically
    await execAsync(`pfctl -f /etc/pf.conf 2>/dev/null`)

    // Add explicit route for VPN network through wg0
    try {
      await execAsync(`route delete -net ${vpnNet} 2>/dev/null`)
    } catch(e) {}
    try {
      await execAsync(`route add -net ${vpnNet} -interface wg0`)
    } catch(e) {}

    return { success: true }
  } catch(e) {
    return { success: false, error: e.message }
  }
}

async function stopWG() {
  try {
    await execAsync('wg-quick down wg0 2>/dev/null || wg-quick down wg0')
    return { success: true }
  } catch(e) {
    return { success: false, error: e.message }
  }
}

async function reloadWG() {
  try {
    const { stdout } = await execAsync('wg show wg0 2>/dev/null')
    if (stdout) {
      await execAsync(`wg syncconf wg0 <(wg-quick strip wg0) 2>/dev/null || true`)
    }
  } catch(e) {}
}

async function getStatus() {
  try {
    const { stdout } = await execAsync('wg show wg0 2>/dev/null')
    if (!stdout.trim()) return { running: false, peers: [] }

    const lines = stdout.split('\n')
    const peers = []
    let currentPeer = null

    for (const line of lines) {
      if (line.startsWith('peer:')) {
        if (currentPeer) peers.push(currentPeer)
        currentPeer = { publicKey: line.split(':')[1].trim() }
      } else if (currentPeer) {
        if (line.includes('endpoint:')) currentPeer.endpoint = line.split('endpoint:')[1].trim()
        if (line.includes('latest handshake:')) currentPeer.lastHandshake = line.split('latest handshake:')[1].trim()
        if (line.includes('transfer:')) currentPeer.transfer = line.split('transfer:')[1].trim()
      }
    }
    if (currentPeer) peers.push(currentPeer)

    return { running: true, peers }
  } catch(e) {
    return { running: false, peers: [] }
  }
}

module.exports = {
  getStatus, getConfig, saveConfig, getServerKeys,
  getPeers, addPeer, deletePeer, togglePeer,
  getPeerConfig, startWG, stopWG, generateWGConf
}
