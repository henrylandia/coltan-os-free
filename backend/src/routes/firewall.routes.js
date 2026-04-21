'use strict'

const { getRules, getStatus, getConfig, saveConfig, enablePF, disablePF } = require('../services/firewall.service')

async function firewallRoutes(fastify, options) {

  fastify.get('/api/firewall/status', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    const status = await getStatus()
    return status
  })

  fastify.get('/api/firewall/rules', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    const rules = await getRules()
    return { rules }
  })

  fastify.get('/api/firewall/config', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    const config = await getConfig()
    return { config }
  })

  fastify.post('/api/firewall/config', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    const { config } = request.body
    if (!config) return reply.code(400).send({ error: 'Config required' })
    await saveConfig(config)
    return { success: true, message: 'Config saved and reloaded' }
  })

  fastify.post('/api/firewall/enable', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    await enablePF()
    return { success: true, message: 'PF enabled' }
  })

  fastify.post('/api/firewall/disable', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    await disablePF()
    return { success: true, message: 'PF disabled' }
  })

}

module.exports = firewallRoutes
