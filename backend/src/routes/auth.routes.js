'use strict'

const { findUser, validatePassword } = require('../services/auth.service')

async function authRoutes(fastify, options) {

  // POST /api/auth/login
  fastify.post('/api/auth/login', async (request, reply) => {
    const { username, password } = request.body

    if (!username || !password) {
      return reply.code(400).send({ error: 'Username and password required' })
    }

    const user = await findUser(username)
    if (!user) {
      return reply.code(401).send({ error: 'Invalid credentials' })
    }

    const valid = await validatePassword(password, user.password)
    if (!valid) {
      return reply.code(401).send({ error: 'Invalid credentials' })
    }

    const token = fastify.jwt.sign({
      id: user.id,
      username: user.username,
      role: user.role
    })

    return reply.send({
      token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role
      }
    })
  })

  // GET /api/auth/me
  fastify.get('/api/auth/me', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    return { user: request.user }
  })

  // POST /api/auth/logout
  fastify.post('/api/auth/logout', async (request, reply) => {
    return { message: 'Logged out successfully' }
  })

}

module.exports = authRoutes
