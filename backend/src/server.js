'use strict'

const fastify = require('fastify')({ logger: true })
const path = require('path')

// Serve frontend
fastify.register(require('@fastify/static'), {
  root: path.join(__dirname, '../../frontend/public'),
  prefix: '/'
})

// API routes
fastify.get('/api/health', async (request, reply) => {
  return {
    status: 'ok',
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  }
})

fastify.get('/api/status', async (request, reply) => {
  return {
    name: 'Coltan OS',
    version: '0.1.0',
    status: 'online'
  }
})

// Start
const start = async () => {
  try {
    await fastify.listen({ port: 3000, host: '0.0.0.0' })
    console.log('Coltan OS running on port 3000')
  } catch (err) {
    fastify.log.error(err)
    process.exit(1)
  }
}

start()
