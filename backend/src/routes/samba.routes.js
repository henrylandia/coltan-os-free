'use strict'

const { getShares, addShare, deleteShare, getUsers, addUser, deleteUser, getStatus } = require('../services/samba.service')

async function sambaRoutes(fastify, options) {

  fastify.get('/api/samba/status', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    return await getStatus()
  })

  fastify.get('/api/samba/shares', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    return { shares: await getShares() }
  })

  fastify.post('/api/samba/shares', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    const { name, path, comment, writable, browseable, validUsers } = request.body
    if (!name || !path) return reply.code(400).send({ error: 'name and path required' })
    return await addShare(name, path, comment, writable, browseable, validUsers)
  })

  fastify.delete('/api/samba/shares/:name', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    return await deleteShare(request.params.name)
  })

  fastify.get('/api/samba/users', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    return { users: await getUsers() }
  })

  fastify.post('/api/samba/users', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    const { username, password } = request.body
    if (!username || !password) return reply.code(400).send({ error: 'username and password required' })
    return await addUser(username, password)
  })

  fastify.delete('/api/samba/users/:username', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    return await deleteUser(request.params.username)
  })

}

module.exports = sambaRoutes
