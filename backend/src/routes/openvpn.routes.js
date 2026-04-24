'use strict'

const {
  getCertificates, getCAInfo, downloadCert, revokeCert,
  getServers, addServer, deleteServer, startServer, stopServer, getServerStatus, getAllStatus,
  getClients, addClient, deleteClient, getClientOVPN
} = require('../services/openvpn.service')

async function openvpnRoutes(fastify, options) {

  // ── Servers ──────────────────────────────────────────────────────────────

  fastify.get('/api/openvpn/servers', {
    onRequest: [fastify.authenticate]
  }, async (req, reply) => {
    return { servers: await getAllStatus() }
  })

  fastify.post('/api/openvpn/servers', {
    onRequest: [fastify.authenticate]
  }, async (req, reply) => {
    const { name, port, proto, network, netmask, type, dns1, dns2, siteNetwork, siteMask } = req.body
    if (!name || !port) return reply.code(400).send({ error: 'name and port required' })
    return await addServer({ name, port, proto, network, netmask, type, dns1, dns2, siteNetwork, siteMask })
  })

  fastify.delete('/api/openvpn/servers/:id', {
    onRequest: [fastify.authenticate]
  }, async (req, reply) => {
    return await deleteServer(req.params.id)
  })

  fastify.post('/api/openvpn/servers/:id/start', {
    onRequest: [fastify.authenticate]
  }, async (req, reply) => {
    return await startServer(req.params.id)
  })

  fastify.post('/api/openvpn/servers/:id/stop', {
    onRequest: [fastify.authenticate]
  }, async (req, reply) => {
    return await stopServer(req.params.id)
  })

  fastify.get('/api/openvpn/servers/:id/status', {
    onRequest: [fastify.authenticate]
  }, async (req, reply) => {
    return await getServerStatus(req.params.id)
  })

  // ── Certificates ─────────────────────────────────────────────────────────

  fastify.get('/api/openvpn/certificates', {
    onRequest: [fastify.authenticate]
  }, async (req, reply) => {
    return { certificates: await getCertificates() }
  })

  fastify.get('/api/openvpn/certificates/ca-info', {
    onRequest: [fastify.authenticate]
  }, async (req, reply) => {
    return { info: await getCAInfo() }
  })

  fastify.get('/api/openvpn/certificates/download', {
    onRequest: [fastify.authenticate]
  }, async (req, reply) => {
    const { name, type } = req.query
    if (!name || !type) return reply.code(400).send({ error: 'name and type required' })
    const content = await downloadCert(name, type)
    if (!content) return reply.code(404).send({ error: 'Certificate not found' })
    return { content, name, type }
  })

  fastify.post('/api/openvpn/certificates/create', {
    onRequest: [fastify.authenticate]
  }, async (req, reply) => {
    const { name, type } = req.body
    if (!name) return reply.code(400).send({ error: 'name required' })
    try {
      const { createClientCert } = require('../services/openvpn.service')
      const safeName = await createClientCert(name)
      return { success: true, safeName }
    } catch(e) {
      return { success: false, error: e.message }
    }
  })

  fastify.post('/api/openvpn/certificates/revoke', {
    onRequest: [fastify.authenticate]
  }, async (req, reply) => {
    const { name } = req.body
    if (!name) return reply.code(400).send({ error: 'name required' })
    try {
      await revokeCert(name)
      return { success: true }
    } catch(e) {
      return { success: false, error: e.message }
    }
  })

  // ── Clients ───────────────────────────────────────────────────────────────

  fastify.get('/api/openvpn/clients', {
    onRequest: [fastify.authenticate]
  }, async (req, reply) => {
    return { clients: await getClients() }
  })

  fastify.post('/api/openvpn/clients', {
    onRequest: [fastify.authenticate]
  }, async (req, reply) => {
    const { name, serverId } = req.body
    if (!name) return reply.code(400).send({ error: 'name required' })
    return await addClient(name, serverId)
  })

  fastify.delete('/api/openvpn/clients/:id', {
    onRequest: [fastify.authenticate]
  }, async (req, reply) => {
    return await deleteClient(req.params.id)
  })

  fastify.get('/api/openvpn/clients/:id/ovpn', {
    onRequest: [fastify.authenticate]
  }, async (req, reply) => {
    const serverIP = req.query.serverIP || req.hostname
    const config = await getClientOVPN(req.params.id, serverIP)
    if (!config) return reply.code(404).send({ error: 'Client not found' })
    return { config }
  })

}

module.exports = openvpnRoutes
