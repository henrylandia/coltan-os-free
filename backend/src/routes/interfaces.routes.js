'use strict'
const {
  getInterfacesWithRoles, setInterfaceRole, setInterfaceIP, setInterfaceDHCP,
  getWanDNS, setWanDNS
} = require('../services/interfaces.service')
async function interfacesRoutes(fastify, options) {
  fastify.get('/api/interfaces', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    return { interfaces: await getInterfacesWithRoles() }
  })
  fastify.post('/api/interfaces/:name/role', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    const { role, description } = request.body
    if (!role) return reply.code(400).send({ error: 'role required' })
    return await setInterfaceRole(request.params.name, role, description)
  })
  fastify.post('/api/interfaces/:name/ip', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    const { ip, netmask, gateway } = request.body
    if (!ip || !netmask) return reply.code(400).send({ error: 'ip and netmask required' })
    return await setInterfaceIP(request.params.name, ip, netmask, gateway)
  })
  fastify.post('/api/interfaces/:name/dhcp', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    return await setInterfaceDHCP(request.params.name)
  })
  fastify.get('/api/interfaces/wan-dns', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    return await getWanDNS()
  })
  fastify.post('/api/interfaces/wan-dns', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    const { mode, servers } = request.body
    return await setWanDNS(mode, servers)
  })
}
module.exports = interfacesRoutes
