'use strict'

const { getDNSStats,
  getStatus, getSettings, saveSettings,
  enableDNSBlocker, disableDNSBlocker,
  updateBlocklists, getUpdateLog,
  addToWhitelist, removeFromWhitelist,
  addToBlacklist, removeFromBlacklist,
  testDomain
} = require('../services/security.service')

async function securityRoutes(fastify, options) {

  fastify.get('/api/security/status', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await getStatus()
  })

  fastify.get('/api/security/settings', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await getSettings()
  })

  fastify.post('/api/security/settings', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await saveSettings(req.body)
  })

  fastify.post('/api/security/dns/enable', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await enableDNSBlocker()
  })

  fastify.post('/api/security/dns/disable', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await disableDNSBlocker()
  })

  fastify.post('/api/security/dns/update', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await updateBlocklists(req.body.lists)
  })

  fastify.get('/api/security/dns/log', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return { log: await getUpdateLog() }
  })

  fastify.post('/api/security/dns/test', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const { domain } = req.body
    if (!domain) return reply.code(400).send({ error: 'domain required' })
    return await testDomain(domain)
  })

  fastify.post('/api/security/whitelist', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const { domain } = req.body
    if (!domain) return reply.code(400).send({ error: 'domain required' })
    return await addToWhitelist(domain)
  })

  fastify.delete('/api/security/whitelist/:domain', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await removeFromWhitelist(req.params.domain)
  })

  fastify.post('/api/security/blacklist', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const { domain } = req.body
    if (!domain) return reply.code(400).send({ error: 'domain required' })
    return await addToBlacklist(domain)
  })

  fastify.delete('/api/security/blacklist/:domain', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await removeFromBlacklist(req.params.domain)
  })

  fastify.get('/api/security/dns/stats', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await getDNSStats()
  })
}

module.exports = securityRoutes
