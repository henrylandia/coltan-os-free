'use strict'

const {
  getSettings, saveSettings, getInterfaces,
  getStatus, start, stop,
  getAlerts, clearAlerts
} = require('../services/suricata.service')

async function suricataRoutes(fastify, options) {

  fastify.get('/api/suricata/status', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await getStatus()
  })

  fastify.get('/api/suricata/settings', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await getSettings()
  })

  fastify.post('/api/suricata/settings', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await saveSettings(req.body)
  })

  fastify.get('/api/suricata/interfaces', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return { interfaces: await getInterfaces() }
  })

  fastify.post('/api/suricata/start', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const settings = req.body
    if (!settings.interface) return reply.code(400).send({ error: 'interface required' })
    return await start(settings)
  })

  fastify.post('/api/suricata/stop', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await stop()
  })

  fastify.get('/api/suricata/alerts', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const limit = parseInt(req.query.limit) || 50
    return { alerts: await getAlerts(limit) }
  })

  fastify.post('/api/suricata/alerts/clear', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await clearAlerts()
  })

}

module.exports = suricataRoutes
