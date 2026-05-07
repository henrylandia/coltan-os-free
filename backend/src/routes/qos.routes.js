'use strict'

const { getRules, addRule, updateRule, deleteRule, toggleRule, applyQoS, getStats } = require('../services/qos.service')

async function qosRoutes(fastify, options) {

  fastify.get('/api/qos/rules', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return { rules: await getRules() }
  })

  fastify.post('/api/qos/rules', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await addRule(req.body)
  })

  fastify.put('/api/qos/rules/:id', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await updateRule(req.params.id, req.body)
  })

  fastify.delete('/api/qos/rules/:id', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await deleteRule(req.params.id)
  })

  fastify.post('/api/qos/rules/:id/toggle', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await toggleRule(req.params.id)
  })

  fastify.post('/api/qos/apply', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await applyQoS()
  })

  fastify.get('/api/qos/stats', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await getStats()
  })

}

module.exports = qosRoutes
