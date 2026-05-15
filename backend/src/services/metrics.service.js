'use strict'
const { exec } = require('child_process')
const { promisify } = require('util')
const execAsync = promisify(exec)

async function getCPU() {
  try {
    const { stdout } = await execAsync('sysctl -n kern.cp_time')
    const vals = stdout.trim().split(' ').map(Number)
    const [user, nice, sys, intr, idle] = vals
    const total = user + nice + sys + intr + idle
    const used = total - idle
    return parseFloat(((used / total) * 100).toFixed(1))
  } catch(e) { return 0 }
}

async function getMemory() {
  try {
    const { stdout: pagesize } = await execAsync('sysctl -n hw.pagesize')
    const { stdout: inactive } = await execAsync('sysctl -n vm.stats.vm.v_inactive_count')
    const { stdout: cache } = await execAsync('sysctl -n vm.stats.vm.v_cache_count')
    const { stdout: free } = await execAsync('sysctl -n vm.stats.vm.v_free_count')
    const { stdout: total } = await execAsync('sysctl -n hw.physmem')
    const ps = parseInt(pagesize.trim())
    const freeBytes = (parseInt(inactive.trim()) + parseInt(cache.trim()) + parseInt(free.trim())) * ps
    const totalBytes = parseInt(total.trim())
    const usedBytes = totalBytes - freeBytes
    const percent = parseFloat(((usedBytes / totalBytes) * 100).toFixed(1))
    const usedGB = (usedBytes / 1024 / 1024 / 1024).toFixed(1)
    const totalGB = (totalBytes / 1024 / 1024 / 1024).toFixed(1)
    return { percent, used: usedGB, total: totalGB, label: `${usedGB}/${totalGB}GB` }
  } catch(e) { return { percent: 0, used: 0, total: 0, label: 'N/A' } }
}

async function getDisk() {
  try {
    const { stdout } = await execAsync('df -h / | tail -1')
    const parts = stdout.trim().split(/\s+/)
    return { used: parts[2], total: parts[1], percent: parseInt(parts[4]), label: `${parts[2]}/${parts[1]}` }
  } catch(e) { return { used: 0, total: 0, percent: 0, label: 'N/A' } }
}

async function getUptime() {
  try {
    const { stdout } = await execAsync('sysctl -n kern.boottime')
    const match = stdout.match(/sec = (\d+)/)
    if (match) {
      const bootTime = parseInt(match[1])
      const now = Math.floor(Date.now() / 1000)
      const uptime = now - bootTime
      const d = Math.floor(uptime / 86400)
      const h = Math.floor((uptime % 86400) / 3600)
      const m = Math.floor((uptime % 3600) / 60)
      if (d > 0) return `${d}d ${h}h ${m}m`
      if (h > 0) return `${h}h ${m}m`
      return `${m}m`
    }
    return 'N/A'
  } catch(e) { return 'N/A' }
}

async function getNetworkTraffic() {
  try {
    const { stdout } = await execAsync('netstat -inb | grep -v lo0 | grep -v Link | grep -v Name')
    const ifaces = {}
    stdout.trim().split('\n').forEach(line => {
      const parts = line.trim().split(/\s+/)
      if (parts.length < 10) return
      const name = parts[0].replace(/\*$/, '')
      if (!ifaces[name]) {
        ifaces[name] = {
          name,
          rxBytes: parseInt(parts[7]) || 0,
          txBytes: parseInt(parts[10]) || 0,
          rxPackets: parseInt(parts[4]) || 0,
          txPackets: parseInt(parts[7]) || 0
        }
      }
    })
    return Object.values(ifaces).filter(i => i.name.match(/^(re|em|wg|tun)/))
  } catch(e) { return [] }
}

async function getServices() {
  const services = []

  const checks = [
    { name: 'PF Firewall', cmd: 'pfctl -s info 2>/dev/null | grep -c Enabled', ok: v => v.trim() === '1' },
    { name: 'Kea DHCP', cmd: 'pgrep kea-dhcp4', ok: v => v.trim().length > 0 },
    { name: 'Samba', cmd: 'pgrep smbd', ok: v => v.trim().length > 0 },
    { name: 'WireGuard', cmd: 'ifconfig wg0 2>/dev/null | grep -c UP', ok: v => v.trim() === '1' },
    { name: 'OpenVPN', cmd: 'pgrep openvpn', ok: v => v.trim().length > 0 },
    { name: 'SSH', cmd: 'pgrep sshd', ok: v => v.trim().length > 0 },
    { name: 'PM2 Backend', cmd: 'pm2 list | grep -c online', ok: v => parseInt(v.trim()) > 0 },
  ]

  for (const check of checks) {
    try {
      const { stdout } = await execAsync(check.cmd + ' 2>/dev/null || echo ""')
      services.push({ name: check.name, running: check.ok(stdout) })
    } catch(e) {
      services.push({ name: check.name, running: false })
    }
  }
  return services
}

async function getVPNStatus() {
  const result = { wireguard: { running: false, peers: 0, connected: 0 }, openvpn: { running: false, clients: 0 } }
  try {
    const { stdout } = await execAsync('wg show 2>/dev/null')
    if (stdout.trim()) {
      result.wireguard.running = true
      result.wireguard.peers = (stdout.match(/^peer:/gm) || []).length
      result.wireguard.connected = (stdout.match(/latest handshake/g) || []).length
    }
  } catch(e) {}
  try {
    const { stdout } = await execAsync('pgrep openvpn 2>/dev/null')
    result.openvpn.running = stdout.trim().length > 0
  } catch(e) {}
  return result
}

async function getTopBlockedIPs() {
  try {
    const { stdout } = await execAsync('pfctl -a coltan/sites -t blocked_sites -T show 2>/dev/null | head -10')
    return stdout.trim().split('\n').filter(Boolean).map(ip => ip.trim())
  } catch(e) { return [] }
}

async function getHardwareInfo() {
  try {
    const [cpuModel, cpuCores, memTotal, memSpeed] = await Promise.all([
      execAsync('sysctl -n hw.model 2>/dev/null').then(r => r.stdout.trim()).catch(() => 'N/A'),
      execAsync('sysctl -n hw.ncpu 2>/dev/null').then(r => r.stdout.trim()).catch(() => 'N/A'),
      execAsync('sysctl -n hw.physmem 2>/dev/null').then(r => (parseInt(r.stdout.trim())/1073741824).toFixed(1)+'GB').catch(() => 'N/A'),
      execAsync('dmidecode -t memory 2>/dev/null | grep -i speed | head -1').then(r => r.stdout.trim()).catch(() => '')
    ])

    // Discos
    let disks = []
    try {
      const { stdout } = await execAsync('geom disk list 2>/dev/null | grep -E "Geom name:|descr:|Mediasize:"')
      const lines = stdout.trim().split('\n')
      let current = {}
      lines.forEach(line => {
        if (line.includes('Geom name:')) { if(current.name) disks.push(current); current = { name: line.split(':')[1].trim() } }
        else if (line.includes('descr:')) current.model = line.split(':').slice(1).join(':').trim()
        else if (line.includes('Mediasize:')) {
          const m = line.match(/(\d+)/)
          if (m) current.size = (parseInt(m[1])/1073741824).toFixed(0)+'GB'
        }
      })
      if (current.name) disks.push(current)
    } catch(e) {}

    return { cpuModel, cpuCores, memTotal, memSpeed, disks }
  } catch(e) { return {} }
}

async function getAllMetrics() {
  const [cpu, memory, disk, uptime, traffic, services, vpn, hardware] = await Promise.all([
    getCPU(), getMemory(), getDisk(), getUptime(),
    getNetworkTraffic(), getServices(), getVPNStatus(), getHardwareInfo()
  ])
  return { cpu, memory, disk, uptime, traffic, services, vpn, hardware, timestamp: Date.now() }
}

module.exports = { getAllMetrics, getCPU, getMemory, getDisk, getUptime, getNetworkTraffic, getServices, getVPNStatus, getHardwareInfo }
