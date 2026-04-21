'use strict'

const {
  getPolicies, addPolicy, deletePolicy, togglePolicy,
  runPolicy, getLog, getSnapshots,
  getSanoidConfig, saveSanoidConfig
} = require('../services/backup.service')

async function backupRoutes(fastify, options) {

  fastify.get('/api/backup/policies', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    return { policies: await getPolicies() }
  })

  fastify.post('/api/backup/policies', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    return await addPolicy(request.body)
  })

  fastify.delete('/api/backup/policies/:id', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    return await deletePolicy(request.params.id)
  })

  fastify.post('/api/backup/policies/:id/toggle', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    return await togglePolicy(request.params.id)
  })

  fastify.post('/api/backup/policies/:id/run', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    return await runPolicy(request.params.id)
  })

  fastify.get('/api/backup/snapshots', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    return { snapshots: await getSnapshots() }
  })

  fastify.get('/api/backup/log', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    return { log: await getLog() }
  })

  fastify.get('/api/backup/sanoid/config', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    return { config: await getSanoidConfig() }
  })

  fastify.post('/api/backup/sanoid/config', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    const { config } = request.body
    if (!config) return reply.code(400).send({ error: 'config required' })
    return await saveSanoidConfig(config)
  })

}

module.exports = backupRoutes
