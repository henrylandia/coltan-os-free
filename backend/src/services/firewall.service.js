'use strict'

const { exec } = require('child_process')
const { promisify } = require('util')
const execAsync = promisify(exec)
const fs = require('fs').promises
const PF_CONF = '/etc/pf.conf'

async function getRules() {
  try {
    const { stdout } = await execAsync('pfctl -sr 2>/dev/null')
    const lines = stdout.trim().split('\n').filter(l => l.trim())
    return lines.map((rule, i) => ({ id: i + 1, rule }))
  } catch(e) {
    return []
  }
}

async function getStatus() {
  try {
    const { stdout } = await execAsync('pfctl -s info 2>/dev/null')
    const enabled = stdout.includes('Enabled')
    const stateMatch = stdout.match(/current entries\s+(\d+)/)
    const states = stateMatch ? parseInt(stateMatch[1]) : 0
    return { enabled, states }
  } catch(e) {
    return { enabled: false, states: 0 }
  }
}

async function getConfig() {
  try {
    const content = await fs.readFile(PF_CONF, 'utf8')
    return content
  } catch(e) {
    return ''
  }
}

async function saveConfig(content) {
  await fs.writeFile(PF_CONF, content, 'utf8')
  await execAsync('pfctl -f /etc/pf.conf 2>/dev/null')
  return true
}

async function enablePF() {
  await execAsync('pfctl -e 2>/dev/null')
  return true
}

async function disablePF() {
  await execAsync('pfctl -d 2>/dev/null')
  return true
}

module.exports = { getRules, getStatus, getConfig, saveConfig, enablePF, disablePF }
