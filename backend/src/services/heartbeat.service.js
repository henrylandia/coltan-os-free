'use strict'
const { exec } = require('child_process')
const { promisify } = require('util')
const execAsync = promisify(exec)
const fs = require('fs').promises
const https = require('https')

const SISTEMA_URL = 'https://sistema.coltanos.com/api/heartbeat'
const LICENSE_FILE = '/usr/local/etc/coltan/license.json'
const LICENSE_STATUS_FILE = '/usr/local/etc/coltan/license-status.json'
const HEARTBEAT_INTERVAL = 5 * 60 * 1000 // 5 minutos

async function getMACAddress() {
  try {
    const roles = JSON.parse(await fs.readFile('/usr/local/etc/coltan/interfaces.json', 'utf8'))
    const wanIface = Object.entries(roles).find(([, v]) => v.role === 'WAN')?.[0] || 're0'
    const { stdout } = await execAsync(`ifconfig ${wanIface} | grep ether | awk '{print $2}'`)
    return stdout.trim() || 'unknown'
  } catch(e) { return 'unknown' }
}

async function getPublicIP() {
  try {
    const { stdout } = await execAsync('fetch -qo - https://api.ipify.org 2>/dev/null || curl -s https://api.ipify.org')
    return stdout.trim()
  } catch(e) { return null }
}

async function getLicenseFile() {
  try {
    const content = await fs.readFile(LICENSE_FILE, 'utf8')
    return content.trim()
  } catch(e) { return null }
}

async function saveLicenseStatus(status) {
  try {
    await fs.writeFile(LICENSE_STATUS_FILE, JSON.stringify({ ...status, updatedAt: new Date().toISOString() }, null, 2))
  } catch(e) {}
}

function sendHeartbeat(payload) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(payload)
    const url = new URL(SISTEMA_URL)
    const options = {
      hostname: url.hostname,
      port: 443,
      path: url.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data)
      },
      rejectUnauthorized: true
    }
    const req = https.request(options, (res) => {
      let body = ''
      res.on('data', chunk => body += chunk)
      res.on('end', () => {
        try { resolve({ status: res.statusCode, data: JSON.parse(body) }) }
        catch(e) { resolve({ status: res.statusCode, data: {} }) }
      })
    })
    req.on('error', reject)
    req.setTimeout(15000, () => { req.destroy(); reject(new Error('timeout')) })
    req.write(data)
    req.end()
  })
}

async function doHeartbeat() {
  try {
    const [hostname, macAddress, publicIP, licenseFile] = await Promise.all([
      execAsync('hostname').then(r => r.stdout.trim()),
      getMACAddress(),
      getPublicIP(),
      getLicenseFile()
    ])

    const payload = {
      hostname,
      macAddress,
      publicIP,
      coltanVersion: '1.0.0',
      licenseFile: licenseFile || undefined
    }

    const result = await sendHeartbeat(payload)

    if (result.status === 200 && result.data.success) {
      await saveLicenseStatus({
        active: result.data.licenseStatus === 'active',
        licenseStatus: result.data.licenseStatus,
        fingerprint: result.data.fingerprint,
        lastHeartbeat: new Date().toISOString()
      })
      console.log('[Heartbeat] OK — licencia:', result.data.licenseStatus)
    } else {
      console.log('[Heartbeat] Error:', result.status, result.data?.error)
      await saveLicenseStatus({
        active: false,
        licenseStatus: 'error',
        error: result.data?.error,
        lastHeartbeat: new Date().toISOString()
      })
    }
  } catch(e) {
    console.log('[Heartbeat] Fallo de conexión:', e.message)
  }
}

function startHeartbeat() {
  console.log('[Heartbeat] Iniciando servicio de heartbeat hacia sistema.coltanos.com')
  doHeartbeat()
  setInterval(doHeartbeat, HEARTBEAT_INTERVAL)
}

module.exports = { startHeartbeat, doHeartbeat }
