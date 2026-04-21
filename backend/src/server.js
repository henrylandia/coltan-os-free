'use strict'

const fastify = require('fastify')({ logger: true })

// Register routes
fastify.get('/', async (request, reply) => {
  return { 
    name: 'Coltan OS',
    version: '0.1.0',
    status: 'online'
  }
})

fastify.get('/health', async (request, reply) => {
  return {
    status: 'ok',
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  }
})

// Start server
const start = async () => {
  try {
    await fastify.listen({ port: 3000, host: '0.0.0.0' })
    console.log('Coltan OS backend running on port 3000')
  } catch (err) {
    fastify.log.error(err)
    process.exit(1)
  }
}

start()
