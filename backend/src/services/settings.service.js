'use strict'

const { exec } = require('child_process')
const { promisify } = require('util')
const execAsync = promisify(exec)
const fs = require('fs').promises

const SETTINGS_FILE = '/usr/local/etc/coltan/settings.json'
const UPDATE_LOG = '/var/log/coltan-update.log'

async function ensureDir() {
  await execAsync('mkdir -p /usr/local/etc/coltan')
}

async function getSettings() {
  try {
    await ensureDir()
    const content = await fs.readFile(SETTINGS_FILE, 'utf8')
    return JSON.parse(content)
  } catch(e) {
    return {
      notifications: { emailEnabled: false, smtpHost: '', smtpPort: 587, smtpUser: '', smtpPass: '', emailTo: '' },
      webhook: { enabled: false, url: '' }
    }
  }
}

async function saveSettings(settings) {
  await ensureDir()
  await fs.writeFile(SETTINGS_FILE, JSON.stringify(settings, null, 2))
  return { success: true }
}

async function getSystemInfo() {
  try {
    const [hostname, timezone, freebsdVersion, nodeVersion, uptime, sambaVersion] = await Promise.all([
      execAsync('hostname').then(r => r.stdout.trim()),
      execAsync('date +%Z').then(r => r.stdout.trim()),
      execAsync('uname -r').then(r => r.stdout.trim()),
      execAsync('node --version').then(r => r.stdout.trim()),
      execAsync('sysctl -n kern.boottime').then(async r => {
        const match = r.stdout.match(/sec = (\d+)/)
        if (match) {
          const up = Math.floor(Date.now()/1000) - parseInt(match[1])
          const d = Math.floor(up/86400), h = Math.floor((up%86400)/3600), m = Math.floor((up%3600)/60)
          return `${d}d ${h}h ${m}m`
        }
        return 'N/A'
      }),
      execAsync('samba --version 2>/dev/null || echo N/A').then(r => r.stdout.trim())
    ])
    return { hostname, timezone, freebsdVersion, nodeVersion, sambaVersion, uptime, coltanVersion: '0.1.0' }
  } catch(e) { return {} }
}

async function setHostname(hostname) {
  try {
    await execAsync(`hostname ${hostname}`)
    await execAsync(`sysrc hostname="${hostname}"`)
    return { success: true }
  } catch(e) { return { success: false, error: e.message } }
}

async function setTimezone(timezone) {
  try {
    await execAsync(`ln -sf /usr/share/zoneinfo/${timezone} /etc/localtime`)
    return { success: true }
  } catch(e) { return { success: false, error: e.message } }
}

async function getDNS() {
  try {
    const content = await fs.readFile('/etc/resolv.conf', 'utf8')
    return content.split('\n').filter(l => l.startsWith('nameserver')).map(l => l.replace('nameserver', '').trim())
  } catch(e) { return [] }
}

async function setDNS(servers) {
  try {
    await fs.writeFile('/etc/resolv.conf', servers.map(s => `nameserver ${s}`).join('\n') + '\n')
    return { success: true }
  } catch(e) { return { success: false, error: e.message } }
}

async function getInterfaces() {
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

async function getNetworkConfig() {
  try {
    const interfaces = await getInterfaces()
    const gwResult = await execAsync('sysrc defaultrouter').catch(() => ({ stdout: '=' }))
    const gateway = gwResult.stdout.split('=')[1]?.trim() || ''
    return { interfaces, gateway }
  } catch(e) { return { interfaces: [], gateway: '' } }
}

async function setInterfaceConfig(iface, ip, netmask, gateway, isDefault) {
  try {
    await execAsync(`sysrc ifconfig_${iface}="inet ${ip} netmask ${netmask}"`)
    if (gateway && isDefault) {
      await execAsync(`sysrc defaultrouter="${gateway}"`)
    }
    // Apply IP change without restarting the whole network
    // Only update the specific interface IP without restart
    // Changes take effect on next reboot or manual restart
    return { success: true, warning: 'Cambios guardados en rc.conf. Aplicar manualmente con: service netif restart (cuidado: puede interrumpir conexión)' }
  } catch(e) { return { success: false, error: e.message } }
}

async function updatePackages() {
  try {
    await fs.writeFile(UPDATE_LOG, `[${new Date().toISOString()}] Starting pkg upgrade...\n`)
    exec(`pkg upgrade -y >> ${UPDATE_LOG} 2>&1`, (err) => {
      const status = err ? 'FAILED' : 'SUCCESS'
      fs.appendFile(UPDATE_LOG, `\n[${new Date().toISOString()}] Update ${status}\n`).catch(() => {})
    })
    return { success: true, message: 'Update started in background. Check log for progress.' }
  } catch(e) { return { success: false, error: e.message } }
}

async function getUpdateLog() {
  try { return await fs.readFile(UPDATE_LOG, 'utf8') } catch(e) { return 'No update log yet' }
}

module.exports = {
  getSettings, saveSettings, getSystemInfo,
  setHostname, setTimezone, getDNS, setDNS,
  getInterfaces, getNetworkConfig, setInterfaceConfig,
  updatePackages, getUpdateLog
}
