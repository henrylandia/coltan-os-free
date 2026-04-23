'use strict'

const {
  getStatus, getConfig, saveConfig, getServerKeys,
  getPeers, addPeer, deletePeer, togglePeer,
  getPeerConfig, startWG, stopWG
} = require('../services/wireguard.service')

async function wireguardRoutes(fastify, options) {

  fastify.get('/api/wireguard/status', {
    onRequest: [fastify.authenticate]
  }, async (req, reply) => {
    return await getStatus()
  })

  fastify.get('/api/wireguard/config', {
    onRequest: [fastify.authenticate]
  }, async (req, reply) => {
    const config = await getConfig()
    const { publicKey } = await getServerKeys()
    return { ...config, publicKey }
  })

  fastify.post('/api/wireguard/config', {
    onRequest: [fastify.authenticate]
  }, async (req, reply) => {
    return await saveConfig(req.body)
  })

  fastify.get('/api/wireguard/peers', {
    onRequest: [fastify.authenticate]
  }, async (req, reply) => {
    return { peers: await getPeers() }
  })

  fastify.post('/api/wireguard/peers', {
    onRequest: [fastify.authenticate]
  }, async (req, reply) => {
    const { name } = req.body
    if (!name) return reply.code(400).send({ error: 'name required' })
    return await addPeer({ name })
  })

  fastify.delete('/api/wireguard/peers/:id', {
    onRequest: [fastify.authenticate]
  }, async (req, reply) => {
    return await deletePeer(req.params.id)
  })

  fastify.post('/api/wireguard/peers/:id/toggle', {
    onRequest: [fastify.authenticate]
  }, async (req, reply) => {
    return await togglePeer(req.params.id)
  })

  fastify.get('/api/wireguard/peers/:id/config', {
    onRequest: [fastify.authenticate]
  }, async (req, reply) => {
    const serverIP = req.query.serverIP || req.hostname
    const config = await getPeerConfig(req.params.id, serverIP)
    if (!config) return reply.code(404).send({ error: 'Peer not found' })
    return { config }
  })

  fastify.post('/api/wireguard/start', {
    onRequest: [fastify.authenticate]
  }, async (req, reply) => {
    return await startWG()
  })

  fastify.post('/api/wireguard/stop', {
    onRequest: [fastify.authenticate]
  }, async (req, reply) => {
    return await stopWG()
  })

}

module.exports = wireguardRoutes
