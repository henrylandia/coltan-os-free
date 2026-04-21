'use strict'

const { getNetworkInfo, getInterfaces } = require('../services/network.service')

async function networkRoutes(fastify, options) {

  fastify.get('/api/network', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    const info = await getNetworkInfo()
    return info
  })

  fastify.get('/api/network/interfaces', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    const interfaces = await getInterfaces()
    return { interfaces }
  })

}

module.exports = networkRoutes
