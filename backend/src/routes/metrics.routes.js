'use strict'
const { getAllMetrics } = require('../services/metrics.service')
const https = require('https')

async function metricsRoutes(fastify, options) {
  fastify.get('/api/metrics', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    const metrics = await getAllMetrics()
    return metrics
  })

  fastify.get('/api/metrics/public-ip', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    return new Promise((resolve) => {
      https.get('https://api.ipify.org?format=json', (res) => {
        let data = ''
        res.on('data', chunk => data += chunk)
        res.on('end', () => {
          try { resolve(JSON.parse(data)) }
          catch(e) { resolve({ ip: '—' }) }
        })
      }).on('error', () => resolve({ ip: '—' }))
    })
  })
}

module.exports = metricsRoutes
