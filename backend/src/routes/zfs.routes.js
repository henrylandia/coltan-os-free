'use strict'

const { getPools, getDatasets, getSnapshots, createSnapshot, deleteSnapshot, createDataset } = require('../services/zfs.service')

async function zfsRoutes(fastify, options) {

  fastify.get('/api/zfs/pools', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    return { pools: await getPools() }
  })

  fastify.get('/api/zfs/datasets', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    return { datasets: await getDatasets() }
  })

  fastify.get('/api/zfs/snapshots', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    return { snapshots: await getSnapshots() }
  })

  fastify.post('/api/zfs/snapshot', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    const { dataset, name } = request.body
    if (!dataset || !name) return reply.code(400).send({ error: 'dataset and name required' })
    return await createSnapshot(dataset, name)
  })

  fastify.delete('/api/zfs/snapshot', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    const { snapshot } = request.body
    if (!snapshot) return reply.code(400).send({ error: 'snapshot required' })
    return await deleteSnapshot(snapshot)
  })

  fastify.post('/api/zfs/dataset', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    const { name, quota, compression } = request.body
    if (!name) return reply.code(400).send({ error: 'name required' })
    return await createDataset(name, { quota, compression })
  })

}

module.exports = zfsRoutes
