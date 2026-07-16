'use strict'

const {
  getStatus, addWan, removeWan, updateConfig, getConfig
} = require('../services/multiwan.service')

async function multiwanRoutes(fastify, options) {

  fastify.get('/api/multiwan/status', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await getStatus()
  })

  fastify.get('/api/multiwan/config', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return getConfig()
  })

  fastify.post('/api/multiwan/config', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const { mode, enabled, checkTarget, checkInterval, failThreshold, recoverThreshold } = req.body
    return await updateConfig({ mode, enabled, checkTarget, checkInterval, failThreshold, recoverThreshold })
  })

  fastify.post('/api/multiwan/wan', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const { iface, gateway, priority, weight } = req.body
    if (!iface) return reply.code(400).send({ error: 'iface requerida' })
    return await addWan(iface, gateway, priority || 1, weight || 1)
  })

  fastify.delete('/api/multiwan/wan/:iface', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await removeWan(req.params.iface)
  })

  fastify.post('/api/multiwan/wan/:iface/toggle', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const config = getConfig()
    const wan = config.wans.find(w => w.iface === req.params.iface)
    if (!wan) return reply.code(404).send({ error: 'WAN no encontrada' })
    wan.enabled = !wan.enabled
    const { saveConfig } = require('../services/multiwan.service')
    return { success: true, enabled: wan.enabled }
  })
}

module.exports = multiwanRoutes
