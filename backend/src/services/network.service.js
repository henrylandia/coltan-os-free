'use strict'

const { exec } = require('child_process')
const { promisify } = require('util')
const execAsync = promisify(exec)

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

      // Skip loopback
      if (name === 'lo0') continue

      const statusMatch = block.match(/status: (\S+)/)
      const status = statusMatch ? statusMatch[1] : 'unknown'

      const ipv4Match = block.match(/inet (\d+\.\d+\.\d+\.\d+)/)
      const ip = ipv4Match ? ipv4Match[1] : null

      const macMatch = block.match(/ether ([\da-f:]+)/)
      const mac = macMatch ? macMatch[1] : null

      const mediaMatch = block.match(/media: (.+)/)
      const media = mediaMatch ? mediaMatch[1].trim() : null

      interfaces.push({ name, status, ip, mac, media })
    }

    return interfaces
  } catch(e) {
    return []
  }
}

async function getRoutes() {
  try {
    const { stdout } = await execAsync('netstat -rn -f inet')
    const lines = stdout.trim().split('\n').slice(4)
    const routes = []

    for (const line of lines) {
      const parts = line.trim().split(/\s+/)
      if (parts.length >= 4) {
        routes.push({
          destination: parts[0],
          gateway: parts[1],
          flags: parts[2],
          interface: parts[parts.length - 1]
        })
      }
    }

    return routes
  } catch(e) {
    return []
  }
}

async function getTraffic() {
  try {
    const { stdout } = await execAsync('netstat -i -b | grep -v lo0')
    const lines = stdout.trim().split('\n').slice(1)
    const traffic = []

    for (const line of lines) {
      const parts = line.trim().split(/\s+/)
      if (parts.length >= 10 && !parts[0].includes('*')) {
        traffic.push({
          interface: parts[0],
          rxBytes: parseInt(parts[7]) || 0,
          txBytes: parseInt(parts[10]) || 0
        })
      }
    }

    return traffic
  } catch(e) {
    return []
  }
}

async function getNetworkInfo() {
  const [interfaces, routes, traffic] = await Promise.all([
    getInterfaces(), getRoutes(), getTraffic()
  ])
  return { interfaces, routes, traffic }
}

module.exports = { getNetworkInfo, getInterfaces, getRoutes, getTraffic }
