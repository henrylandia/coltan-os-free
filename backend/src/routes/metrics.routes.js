'use strict'

const { getAllMetrics } = require('../services/metrics.service')

async function metricsRoutes(fastify, options) {

  fastify.get('/api/metrics', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    const metrics = await getAllMetrics()
    return metrics
  })

}

module.exports = metricsRoutes
