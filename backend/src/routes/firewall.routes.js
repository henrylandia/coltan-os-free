'use strict'

const {
  getStatus, getConfig, saveConfig, enablePF, disablePF, getPFRules,
  getRules, addRule, updateRule, deleteRule, toggleRule, reorderRules,
  getBlockedIPs, blockIP, unblockIP,
  getPortForwards, addPortForward, deletePortForward,
  generateAndReload
} = require('../services/firewall.service')

async function firewallRoutes(fastify, options) {

  // Status
  fastify.get('/api/firewall/status', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await getStatus()
  })

  fastify.post('/api/firewall/enable', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await enablePF()
  })

  fastify.post('/api/firewall/disable', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await disablePF()
  })

  // Config
  fastify.get('/api/firewall/config', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return { config: await getConfig() }
  })

  fastify.post('/api/firewall/config', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const { config } = req.body
    if (!config) return reply.code(400).send({ error: 'config required' })
    return await saveConfig(config)
  })

  fastify.get('/api/firewall/rules/active', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return { rules: await getPFRules() }
  })

  // Reload
  fastify.post('/api/firewall/reload', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await generateAndReload()
  })

  // Custom rules
  fastify.get('/api/firewall/rules', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return { rules: await getRules() }
  })

  fastify.post('/api/firewall/rules', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await addRule(req.body)
  })

  fastify.put('/api/firewall/rules/:id', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await updateRule(req.params.id, req.body)
  })

  fastify.post('/api/firewall/rules/reorder', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await reorderRules(req.body.ids)
  })

  fastify.delete('/api/firewall/rules/:id', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await deleteRule(req.params.id)
  })

  fastify.post('/api/firewall/rules/:id/toggle', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await toggleRule(req.params.id)
  })

  // Blocked IPs
  fastify.get('/api/firewall/blocked-ips', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return { ips: await getBlockedIPs() }
  })

  fastify.post('/api/firewall/blocked-ips', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const { ip, description } = req.body
    if (!ip) return reply.code(400).send({ error: 'ip required' })
    return await blockIP(ip, description)
  })

  fastify.delete('/api/firewall/blocked-ips/:ip', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await unblockIP(req.params.ip)
  })

  // Port forwarding
  fastify.get('/api/firewall/port-forwards', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return { forwards: await getPortForwards() }
  })

  fastify.post('/api/firewall/port-forwards', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const { protocol, extPort, intIP, intPort, description } = req.body
    if (!extPort || !intIP || !intPort) return reply.code(400).send({ error: 'extPort, intIP and intPort required' })
    return await addPortForward({ protocol, extPort, intIP, intPort, description })
  })

  fastify.put('/api/firewall/port-forwards/:id', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const { protocol, extPort, intIP, intPort, description } = req.body
    await deletePortForward(req.params.id)
    return await addPortForward({ protocol, extPort, intIP, intPort, description })
  })

  fastify.delete('/api/firewall/port-forwards/:id', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await deletePortForward(req.params.id)
  })

}

module.exports = firewallRoutes
