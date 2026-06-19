'use strict'
const {
  getSettings, getInterfaces,
  getStatus, start, stop,
  getAlerts
} = require('../services/suricata.service')

async function suricataRoutes(fastify, options) {
  fastify.get('/api/suricata/status', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await getStatus()
  })
  fastify.get('/api/suricata/settings', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await getSettings()
  })
  fastify.get('/api/suricata/interfaces', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return { interfaces: await getInterfaces() }
  })
  fastify.post('/api/suricata/start', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const settings = req.body
    if (!settings.interface) return reply.code(400).send({ error: 'interface required' })
    // Version free: forzar siempre modo IDS, sin importar lo que se envie
    settings.mode = 'ids'
    return await start(settings)
  })
  fastify.post('/api/suricata/stop', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await stop()
  })
  fastify.get('/api/suricata/alerts', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const limit = parseInt(req.query.limit) || 50
    return { alerts: await getAlerts(limit) }
  })
  // Endpoints premium bloqueados explicitamente en version free
  fastify.post('/api/suricata/settings', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return reply.code(403).send({ error: 'Esta funcion requiere Coltan OS Premium', feature: 'premium' })
  })
  fastify.post('/api/suricata/alerts/clear', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return reply.code(403).send({ error: 'Esta funcion requiere Coltan OS Premium', feature: 'premium' })
  })
}

module.exports = suricataRoutes
