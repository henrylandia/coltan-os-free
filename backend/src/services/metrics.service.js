'use strict'

const { exec } = require('child_process')
const { promisify } = require('util')
const execAsync = promisify(exec)

async function getCPU() {
  try {
    const { stdout } = await execAsync("sysctl -n kern.cp_time")
    const vals = stdout.trim().split(' ').map(Number)
    const user = vals[0], nice = vals[1], sys = vals[2], intr = vals[3], idle = vals[4]
    const total = user + nice + sys + intr + idle
    const used = total - idle
    const percent = ((used / total) * 100).toFixed(1)
    return `${percent}%`
  } catch(e) {
    return 'N/A'
  }
}

async function getMemory() {
  try {
    const { stdout: pagesize } = await execAsync("sysctl -n hw.pagesize")
    const { stdout: inactive } = await execAsync("sysctl -n vm.stats.vm.v_inactive_count")
    const { stdout: cache } = await execAsync("sysctl -n vm.stats.vm.v_cache_count")
    const { stdout: free } = await execAsync("sysctl -n vm.stats.vm.v_free_count")
    const { stdout: total } = await execAsync("sysctl -n hw.physmem")

    const ps = parseInt(pagesize.trim())
    const freeBytes = (parseInt(inactive.trim()) + parseInt(cache.trim()) + parseInt(free.trim())) * ps
    const totalBytes = parseInt(total.trim())
    const usedBytes = totalBytes - freeBytes
    const percent = ((usedBytes / totalBytes) * 100).toFixed(1)
    const usedGB = (usedBytes / 1024 / 1024 / 1024).toFixed(1)
    const totalGB = (totalBytes / 1024 / 1024 / 1024).toFixed(1)

    return `${usedGB}/${totalGB}GB`
  } catch(e) {
    return 'N/A'
  }
}

async function getDisk() {
  try {
    const { stdout } = await execAsync("df -h / | tail -1")
    const parts = stdout.trim().split(/\s+/)
    const used = parts[2]
    const total = parts[1]
    const percent = parts[4]
    return `${used}/${total}`
  } catch(e) {
    return 'N/A'
  }
}

async function getUptime() {
  try {
    const { stdout } = await execAsync("sysctl -n kern.boottime")
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
  } catch(e) {
    return 'N/A'
  }
}

async function getAllMetrics() {
  const [cpu, memory, disk, uptime] = await Promise.all([
    getCPU(), getMemory(), getDisk(), getUptime()
  ])
  return { cpu, memory, disk, uptime }
}

module.exports = { getAllMetrics, getCPU, getMemory, getDisk, getUptime }
