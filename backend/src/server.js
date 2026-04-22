'use strict'

const fastify = require('fastify')({ logger: true })
const path = require('path')
const config = require('./config')
const { initDefaultAdmin } = require('./services/auth.service')

// Plugins
fastify.register(require('@fastify/formbody'))

// Handle empty JSON body gracefully
fastify.addHook('preValidation', async (request, reply) => {
  if (!request.body && (request.method === 'DELETE' || request.method === 'POST' || request.method === 'PUT')) {
    request.body = {}
  }
})


// JWT plugin
fastify.register(require('@fastify/jwt'), {
  secret: config.JWT_SECRET,
  sign: { expiresIn: config.JWT_EXPIRES }
})

// Authenticate decorator
fastify.decorate('authenticate', async function(request, reply) {
  try {
    await request.jwtVerify()
  } catch (err) {
    reply.code(401).send({ error: 'Unauthorized' })
  }
})

// Serve frontend
fastify.register(require('@fastify/static'), {
  root: path.join(__dirname, '../../frontend/public'),
  prefix: '/'
})

// Public routes
fastify.register(require('./routes/auth.routes'))
fastify.register(require('./routes/metrics.routes'))
fastify.register(require('./routes/network.routes'))
fastify.register(require('./routes/firewall.routes'))
fastify.register(require('./routes/zfs.routes'))
fastify.register(require('./routes/samba.routes'))
fastify.register(require('./routes/backup.routes'))
fastify.register(require('./routes/settings.routes'))
fastify.register(require('./routes/dashboard.routes'))
fastify.register(require('./routes/dhcp.routes'))
fastify.register(require('./routes/interfaces.routes'))

// WebSockets
fastify.register(require('@fastify/websocket'))
fastify.register(require('./routes/ws.routes'))
fastify.register(require('./routes/console.routes'))

// Public health
fastify.get('/api/health', async (request, reply) => {
  return {
    status: 'ok',
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  }
})

// Protected routes
fastify.register(async function(fastify) {
  fastify.addHook('onRequest', fastify.authenticate)

  fastify.get('/api/status', async (request, reply) => {
    return {
      name: 'Coltan OS',
      version: '0.1.0',
      status: 'online',
      user: request.user.username
    }
  })
})

// Start
const start = async () => {
  try {
    await initDefaultAdmin()
    await fastify.listen({ port: config.PORT, host: config.HOST })
    console.log(`Coltan OS running on port ${config.PORT}`)
  } catch (err) {
    fastify.log.error(err)
    process.exit(1)
  }
}

start()
