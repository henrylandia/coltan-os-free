'use strict'

const fp = require('fastify-plugin')
const config = require('../config')

async function authPlugin(fastify, options) {
  fastify.register(require('@fastify/jwt'), {
    secret: config.JWT_SECRET,
    sign: { expiresIn: config.JWT_EXPIRES }
  })

  fastify.decorate('authenticate', async function(request, reply) {
    try {
      await request.jwtVerify()
    } catch (err) {
      reply.code(401).send({ error: 'Unauthorized' })
    }
  })
}

module.exports = fp(authPlugin)
