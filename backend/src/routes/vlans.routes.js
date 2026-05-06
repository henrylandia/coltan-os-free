'use strict'

const { getVLANs, createVLAN, deleteVLAN, updateVLAN, getLANParents } = require('../services/vlans.service')

async function vlanRoutes(fastify, options) {

  fastify.get('/api/vlans', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return { vlans: await getVLANs() }
  })

  fastify.get('/api/vlans/parents', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return { interfaces: await getLANParents() }
  })

  fastify.post('/api/vlans', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const { tag, parent, ip, netmask, description } = req.body
    return await createVLAN({ tag, parent, ip, netmask, description })
  })

  fastify.put('/api/vlans/:id', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await updateVLAN(req.params.id, req.body)
  })

  fastify.delete('/api/vlans/:id', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await deleteVLAN(req.params.id)
  })

}

module.exports = vlanRoutes
