'use strict'

const {
  getStatus, getSubnets, addSubnet, deleteSubnet,
  addReservation, deleteReservation, getLeases,
  startKea, stopKea, restartKea
} = require('../services/dhcp.service')

async function dhcpRoutes(fastify, options) {

  fastify.get('/api/dhcp/status', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await getStatus()
  })

  fastify.get('/api/dhcp/subnets', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return { subnets: await getSubnets() }
  })

  fastify.post('/api/dhcp/subnets', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const { subnet, poolStart, poolEnd, gateway, dns, domain, leaseTime, interface: iface } = req.body
    if (!subnet || !poolStart || !poolEnd || !gateway)
      return reply.code(400).send({ error: 'subnet, poolStart, poolEnd and gateway required' })
    return await addSubnet({ subnet, poolStart, poolEnd, gateway, dns, domain, leaseTime, interface: iface })
  })

  fastify.delete('/api/dhcp/subnets/:id', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await deleteSubnet(req.params.id)
  })

  fastify.post('/api/dhcp/subnets/:id/reservations', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const { mac, ip, hostname } = req.body
    if (!mac || !ip) return reply.code(400).send({ error: 'mac and ip required' })
    return await addReservation(req.params.id, mac, ip, hostname)
  })

  fastify.delete('/api/dhcp/subnets/:id/reservations/:mac', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await deleteReservation(req.params.id, req.params.mac)
  })

  fastify.get('/api/dhcp/leases', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return { leases: await getLeases() }
  })

  fastify.post('/api/dhcp/leases/clear', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    try {
      const fs = require('fs').promises
      await fs.writeFile('/var/db/kea/dhcp4.leases', '').catch(() => {})
      await fs.writeFile('/var/db/kea/dhcp4.leases.2', '').catch(() => {})
      restartKea()
      return { success: true }
    } catch(e) { return { success: false, error: e.message } }
  })

  fastify.post('/api/dhcp/start', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await startKea()
  })

  fastify.post('/api/dhcp/stop', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await stopKea()
  })

}

module.exports = dhcpRoutes
