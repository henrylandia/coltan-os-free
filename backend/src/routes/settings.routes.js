'use strict'

const nodemailer = require('nodemailer')
const {
  getSettings, saveSettings, getSystemInfo,
  setHostname, setTimezone, getDNS, setDNS,
  getInterfaces, getNetworkConfig, setInterfaceConfig,
  updatePackages, getUpdateLog
} = require('../services/settings.service')

async function settingsRoutes(fastify, options) {

  fastify.get('/api/settings', { onRequest: [fastify.authenticate] }, async (request, reply) => {
    return await getSettings()
  })

  fastify.post('/api/settings', { onRequest: [fastify.authenticate] }, async (request, reply) => {
    return await saveSettings(request.body)
  })

  fastify.get('/api/settings/sysinfo', { onRequest: [fastify.authenticate] }, async (request, reply) => {
    return await getSystemInfo()
  })

  fastify.post('/api/settings/hostname', { onRequest: [fastify.authenticate] }, async (request, reply) => {
    const { hostname } = request.body
    if (!hostname) return reply.code(400).send({ error: 'hostname required' })
    return await setHostname(hostname)
  })

  fastify.post('/api/settings/timezone', { onRequest: [fastify.authenticate] }, async (request, reply) => {
    const { timezone } = request.body
    if (!timezone) return reply.code(400).send({ error: 'timezone required' })
    return await setTimezone(timezone)
  })

  fastify.get('/api/settings/dns', { onRequest: [fastify.authenticate] }, async (request, reply) => {
    return { servers: await getDNS() }
  })

  fastify.post('/api/settings/dns', { onRequest: [fastify.authenticate] }, async (request, reply) => {
    const { servers } = request.body
    if (!servers) return reply.code(400).send({ error: 'servers required' })
    return await setDNS(servers)
  })

  fastify.get('/api/settings/network', { onRequest: [fastify.authenticate] }, async (request, reply) => {
    return await getNetworkConfig()
  })

  fastify.get('/api/settings/interfaces', { onRequest: [fastify.authenticate] }, async (request, reply) => {
    return { interfaces: await getInterfaces() }
  })

  fastify.post('/api/settings/interface', { onRequest: [fastify.authenticate] }, async (request, reply) => {
    const { iface, ip, netmask, gateway, isDefault } = request.body
    if (!iface || !ip || !netmask) return reply.code(400).send({ error: 'iface, ip and netmask required' })
    return await setInterfaceConfig(iface, ip, netmask, gateway, isDefault)
  })

  fastify.post('/api/settings/reboot', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    setTimeout(() => require('child_process').exec('reboot'), 1000)
    return { success: true }
  })

  fastify.post('/api/settings/shutdown', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    setTimeout(() => require('child_process').exec('shutdown -p now'), 1000)
    return { success: true }
  })

  fastify.post('/api/settings/update', { onRequest: [fastify.authenticate] }, async (request, reply) => {
    return await updatePackages()
  })

  fastify.get('/api/settings/coltan/version', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const { exec } = require('child_process')
    const { promisify } = require('util')
    const execAsync = promisify(exec)
    try {
      const { stdout: local } = await execAsync('cd /opt/coltanos && git rev-parse --short HEAD 2>/dev/null')
      const { stdout: branch } = await execAsync('cd /opt/coltanos && git rev-parse --abbrev-ref HEAD 2>/dev/null')
      const { stdout: lastCommit } = await execAsync('cd /opt/coltanos && git log -1 --format="%s|%ar" 2>/dev/null')
      const { stdout: remote } = await execAsync('cd /opt/coltanos && git fetch origin 2>/dev/null; git rev-parse --short origin/main 2>/dev/null || echo ""')
      const localHash = local.trim()
      const remoteHash = remote.trim()
      const [message, date] = lastCommit.trim().split('|')
      return {
        localHash, remoteHash, branch: branch.trim(),
        upToDate: localHash === remoteHash || !remoteHash,
        lastCommit: message || '', lastCommitDate: date || '', version: 'v0.1.0'
      }
    } catch(e) { return { error: e.message } }
  })

  fastify.post('/api/settings/coltan/update', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const { exec } = require('child_process')
    const { promisify } = require('util')
    const execAsync = promisify(exec)
    try {
      const { stdout: pull } = await execAsync('cd /opt/coltanos && git pull origin main 2>&1')
      const { stdout: hash } = await execAsync('cd /opt/coltanos && git rev-parse --short HEAD 2>/dev/null')
      setTimeout(() => execAsync('pm2 restart coltanos-backend 2>/dev/null'), 2000)
      return { success: true, output: pull.trim(), hash: hash.trim() }
    } catch(e) { return { success: false, error: e.message } }
  })

  fastify.get('/api/settings/update/log', { onRequest: [fastify.authenticate] }, async (request, reply) => {
    return { log: await getUpdateLog() }
  })

  fastify.post('/api/settings/test-smtp', { onRequest: [fastify.authenticate] }, async (request, reply) => {
    const { host, port, user, pass, to } = request.body
    if (!host || !user || !pass || !to) return reply.code(400).send({ error: 'All fields required' })
    try {
      const transporter = nodemailer.createTransport({
        host, port: parseInt(port),
        secure: parseInt(port) === 465,
        auth: { user, pass }
      })
      await transporter.verify()
      await transporter.sendMail({
        from: user, to,
        subject: 'Coltan OS — Test Email',
        text: 'This is a test email from Coltan OS.'
      })
      return { success: true }
    } catch(e) { return { success: false, error: e.message } }
  })

  fastify.post('/api/settings/test-webhook', { onRequest: [fastify.authenticate] }, async (request, reply) => {
    const { url } = request.body
    if (!url) return reply.code(400).send({ error: 'url required' })
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: 'Coltan OS — Test notification' })
      })
      return { success: res.ok }
    } catch(e) { return { success: false, error: e.message } }
  })

  // Licencia
  fastify.get('/api/settings/license/status', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    try {
      const statusFile = '/usr/local/etc/coltan/license-status.json'
      const data = JSON.parse(require('fs').readFileSync(statusFile, 'utf8'))
      return data
    } catch(e) {
      return { active: false, licenseStatus: 'no_license' }
    }
  })

  fastify.post("/api/settings/license/force-check", { onRequest: [fastify.authenticate] }, async (req, reply) => {
    try {
      const { doHeartbeat } = require("../services/heartbeat.service")
      await doHeartbeat()
      const statusFile = "/usr/local/etc/coltan/license-status.json"
      const status = JSON.parse(require("fs").readFileSync(statusFile, "utf8"))
      return { success: true, ...status }
    } catch(e) {
      return reply.code(500).send({ error: "Error verificando licencia: " + e.message })
    }
  })

  fastify.post('/api/settings/license/apply', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const { licenseFile } = req.body
    if (!licenseFile) return reply.code(400).send({ error: 'licenseFile requerido' })
    const LICENSE_FILE = '/usr/local/etc/coltan/license.json'
    require('fs').writeFileSync(LICENSE_FILE, licenseFile)
    try {
      const { doHeartbeat } = require('../services/heartbeat.service')
      await doHeartbeat()
      const statusFile = '/usr/local/etc/coltan/license-status.json'
      const status = JSON.parse(require('fs').readFileSync(statusFile, 'utf8'))
      if (status.active) {
        const { isUpgradeAvailable, performUpgrade } = require("../services/upgrade.service")
        let upgradeTriggered = false
        if (await isUpgradeAvailable()) {
          upgradeTriggered = true
          performUpgrade().catch(() => {})
        }
        return { success: true, licenseStatus: status.licenseStatus, upgrading: upgradeTriggered }
      } else {
        require("fs").unlinkSync(LICENSE_FILE)
        return reply.code(403).send({ error: status.error || "Licencia invalida o ya activada en otro servidor" })
      }
    } catch(e) {
      return reply.code(500).send({ error: "Error validando licencia: " + e.message })
    }
  })

  fastify.get("/api/settings/upgrade/log", { onRequest: [fastify.authenticate] }, async (req, reply) => {
    try {
      const log = require("fs").readFileSync("/usr/local/etc/coltan/upgrade-log.txt", "utf8")
      return { log }
    } catch(e) {
      return { log: "Sin actualizaciones registradas todavia" }
    }
  })

}

module.exports = settingsRoutes
