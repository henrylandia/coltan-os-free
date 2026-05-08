'use strict'

const {
  getPortals, createPortal, updatePortal, deletePortal, enablePortal, disablePortalById,
  getUsers, createUser, deleteUser, updateUser,
  getGroups, createGroup, deleteGroup, updateGroup,
  getSessions, cleanExpiredSessions, killSession, killAllSessions,
  authenticatePortal
} = require('../services/captive.service')

async function captiveRoutes(fastify, options) {

  // ── PUBLIC (no auth) — used by captive portal page ──────────────────────────

  // Auth endpoint called from portal page
  fastify.post('/api/captive/auth', async (req, reply) => {
    const ip = req.headers['x-real-ip'] || req.ip
    const { portalId, username, password } = req.body
    if (!portalId) return reply.code(400).send({ success: false, error: 'portalId required' })
    return await authenticatePortal(ip, portalId, username, password)
  })

  // Serve portal HTML based on client IP
  fastify.get('/api/captive/portal', async (req, reply) => {
    const ip = req.query.ip || req.ip
    const portals = await getPortals()
    // Find portal for this client's interface
    // For now return first enabled portal HTML
    const portal = portals.find(p => p.enabled)
    if (!portal) return reply.code(404).send('No portal configured')
    const fs = require('fs')
    const htmlPath = `/opt/coltanos/captive-portal/templates/${portal.id}.html`
    try {
      const html = fs.readFileSync(htmlPath, 'utf8')
      reply.header('Content-Type', 'text/html').send(html)
    } catch(e) {
      reply.code(404).send('Portal not found')
    }
  })

  // ── ADMIN (requires auth) ────────────────────────────────────────────────────

  // Portals
  fastify.get('/api/captive/portals', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return { portals: await getPortals() }
  })

  fastify.post('/api/captive/portals', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await createPortal(req.body)
  })

  fastify.put('/api/captive/portals/:id', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await updatePortal(req.params.id, req.body)
  })

  fastify.delete('/api/captive/portals/:id', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await deletePortal(req.params.id)
  })

  fastify.post('/api/captive/portals/:id/enable', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await enablePortal(req.params.id)
  })

  fastify.post('/api/captive/portals/:id/disable', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await disablePortalById(req.params.id)
  })

  // Users
  fastify.get('/api/captive/users', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const users = await getUsers()
    return { users: users.map(u => ({ ...u, password: undefined })) }
  })

  fastify.post('/api/captive/users', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await createUser(req.body)
  })

  fastify.put('/api/captive/users/:id', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await updateUser(req.params.id, req.body)
  })

  fastify.delete('/api/captive/users/:id', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await deleteUser(req.params.id)
  })

  // Groups
  fastify.get('/api/captive/groups', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return { groups: await getGroups() }
  })

  fastify.post('/api/captive/groups', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await createGroup(req.body)
  })

  fastify.delete('/api/captive/groups/:id', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await deleteGroup(req.params.id)
  })

  // Sessions
  fastify.get('/api/captive/sessions', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    await cleanExpiredSessions()
    return { sessions: await getSessions() }
  })

  fastify.post('/api/captive/sessions/clean', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await cleanExpiredSessions()
  })

  // Interfaces available for portals
  fastify.get('/api/captive/interfaces', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    try {
      const fs = require('fs')
      const ifaces = JSON.parse(fs.readFileSync('/usr/local/etc/coltan/interfaces.json', 'utf8'))
      const lan = Object.entries(ifaces)
        .filter(([, v]) => v.role === 'LAN' || v.role?.startsWith('OPT') || v.vlan)
        .map(([name, v]) => ({ name, role: v.role, description: v.description || name }))
      return { interfaces: lan }
    } catch(e) { return { interfaces: [] } }
  })
  // Update group
  fastify.put('/api/captive/groups/:id', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await updateGroup(req.params.id, req.body)
  })

  // Kill single session
  fastify.delete('/api/captive/sessions/:id', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await killSession(req.params.id)
  })

  // Kill all sessions
  fastify.post('/api/captive/sessions/killall', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await killAllSessions()
  })

}

module.exports = captiveRoutes
