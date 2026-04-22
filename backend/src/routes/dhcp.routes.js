'use strict'

const {
  getStatus, getSubnets, addSubnet, deleteSubnet,
  addReservation, deleteReservation, getLeases,
  startKea, stopKea
} = require('../services/dhcp.service')

async function dhcpRoutes(fastify, options) {

  fastify.get('/api/dhcp/status', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    return await getStatus()
  })

  fastify.get('/api/dhcp/subnets', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    return { subnets: await getSubnets() }
  })

  fastify.post('/api/dhcp/subnets', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    const { subnet, poolStart, poolEnd, gateway, dns, domain, leaseTime, interface: iface } = request.body
    if (!subnet || !poolStart || !poolEnd || !gateway) {
      return reply.code(400).send({ error: 'subnet, poolStart, poolEnd and gateway required' })
    }
    return await addSubnet({ subnet, poolStart, poolEnd, gateway, dns, domain, leaseTime, interface: iface })
  })

  fastify.delete('/api/dhcp/subnets/:id', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    return await deleteSubnet(request.params.id)
  })

  fastify.post('/api/dhcp/subnets/:id/reservations', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    const { mac, ip, hostname } = request.body
    if (!mac || !ip) return reply.code(400).send({ error: 'mac and ip required' })
    return await addReservation(request.params.id, { mac, ip, hostname })
  })

  fastify.delete('/api/dhcp/subnets/:id/reservations/:mac', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    return await deleteReservation(request.params.id, request.params.mac)
  })

  fastify.get('/api/dhcp/leases', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    return { leases: await getLeases() }
  })

  fastify.post('/api/dhcp/start', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    return await startKea()
  })

  fastify.post('/api/dhcp/stop', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    return await stopKea()
  })

}

module.exports = dhcpRoutes
