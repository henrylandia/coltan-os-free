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
    const { exec } = require('child_process')
    const { promisify } = require('util')
    const execAsync = promisify(exec)

    // 1. Save config
    await saveConfig(req.body)

    // 2. Regenerate wg0.conf
    const { generateWGConf } = require('../services/wireguard.service')
    await generateWGConf()

    // 3. Restart WireGuard
    try { await execAsync('wg-quick down wg0 2>/dev/null') } catch(e) {}
    await new Promise(r => setTimeout(r, 1000))
    try { await execAsync('wg-quick up wg0') } catch(e) {}

    // 4. Reload PF firewall with new VPN network
    await new Promise(r => setTimeout(r, 500))
    const { generateAndReload } = require('../services/firewall.service')
    await generateAndReload()

    return { success: true }
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
    const result = await startWG()
    // Always reload firewall after starting WG
    if (result.success) {
      const { generateAndReload } = require('../services/firewall.service')
      await generateAndReload()
    }
    return result
  })

  fastify.post('/api/wireguard/stop', {
    onRequest: [fastify.authenticate]
  }, async (req, reply) => {
    return await stopWG()
  })

}

module.exports = wireguardRoutes
