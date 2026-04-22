'use strict'

const nodemailer = require('nodemailer')
const {
  getSettings, saveSettings, getSystemInfo,
  setHostname, setTimezone, getDNS, setDNS,
  getInterfaces, getNetworkConfig, setInterfaceConfig,
  updatePackages, getUpdateLog
} = require('../services/settings.service')

async function settingsRoutes(fastify, options) {

  fastify.get('/api/settings', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    return await getSettings()
  })

  fastify.post('/api/settings', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    return await saveSettings(request.body)
  })

  fastify.get('/api/settings/sysinfo', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    return await getSystemInfo()
  })

  fastify.post('/api/settings/hostname', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    const { hostname } = request.body
    if (!hostname) return reply.code(400).send({ error: 'hostname required' })
    return await setHostname(hostname)
  })

  fastify.post('/api/settings/timezone', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    const { timezone } = request.body
    if (!timezone) return reply.code(400).send({ error: 'timezone required' })
    return await setTimezone(timezone)
  })

  fastify.get('/api/settings/dns', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    return { servers: await getDNS() }
  })

  fastify.post('/api/settings/dns', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    const { servers } = request.body
    if (!servers) return reply.code(400).send({ error: 'servers required' })
    return await setDNS(servers)
  })

  fastify.get('/api/settings/network', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    return await getNetworkConfig()
  })

  fastify.get('/api/settings/interfaces', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    return { interfaces: await getInterfaces() }
  })

  fastify.post('/api/settings/interface', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    const { iface, ip, netmask, gateway } = request.body
    if (!iface || !ip || !netmask) return reply.code(400).send({ error: 'iface, ip and netmask required' })
    return await setInterfaceConfig(iface, ip, netmask, gateway)
  })

  fastify.post('/api/settings/update', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    return await updatePackages()
  })

  fastify.get('/api/settings/update/log', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    return { log: await getUpdateLog() }
  })

  fastify.post('/api/settings/test-smtp', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
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
    } catch(e) {
      return { success: false, error: e.message }
    }
  })

  fastify.post('/api/settings/test-webhook', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    const { url } = request.body
    if (!url) return reply.code(400).send({ error: 'url required' })
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: 'Coltan OS — Test notification' })
      })
      return { success: res.ok }
    } catch(e) {
      return { success: false, error: e.message }
    }
  })

}

module.exports = settingsRoutes
