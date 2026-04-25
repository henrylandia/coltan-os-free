'use strict'

const {
  getCategories, updateCategory, createCategory, deleteCategory,
  getGroups, createGroup, deleteGroup, toggleGroup,
  addEntryToGroup, removeEntryFromGroup,
  createGroupFromCategory, refreshDNS, applyBlocking, getStats
} = require('../services/sites.service')

async function sitesRoutes(fastify, options) {

  // Stats
  fastify.get('/api/sites/stats', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await getStats()
  })

  // Categories
  fastify.get('/api/sites/categories', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return { categories: await getCategories() }
  })

  fastify.post('/api/sites/categories', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const { name, icon, domains } = req.body
    if (!name) return reply.code(400).send({ error: 'name required' })
    return await createCategory({ name, icon, domains })
  })

  fastify.put('/api/sites/categories/:id', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await updateCategory(req.params.id, req.body)
  })

  fastify.delete('/api/sites/categories/:id', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await deleteCategory(req.params.id)
  })

  // Groups
  fastify.get('/api/sites/groups', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return { groups: await getGroups() }
  })

  fastify.post('/api/sites/groups', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const { name, description, entries, applyTo, applyToValue } = req.body
    if (!name) return reply.code(400).send({ error: 'name required' })
    return await createGroup({ name, description, entries, applyTo, applyToValue })
  })

  fastify.delete('/api/sites/groups/:id', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await deleteGroup(req.params.id)
  })

  fastify.post('/api/sites/groups/:id/toggle', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await toggleGroup(req.params.id)
  })

  fastify.post('/api/sites/groups/:id/entries', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const { type, value } = req.body
    if (!value) return reply.code(400).send({ error: 'value required' })
    return await addEntryToGroup(req.params.id, { type, value })
  })

  fastify.delete('/api/sites/groups/:groupId/entries/:entryId', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await removeEntryFromGroup(req.params.groupId, req.params.entryId)
  })

  // Block from category
  fastify.post('/api/sites/groups/from-category', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const { categoryId, name, applyTo, applyToValue } = req.body
    if (!categoryId) return reply.code(400).send({ error: 'categoryId required' })
    return await createGroupFromCategory(categoryId, name, applyTo, applyToValue)
  })

  // Refresh DNS
  fastify.post('/api/sites/refresh-dns', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await refreshDNS()
  })

  // Apply
  fastify.post('/api/sites/apply', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await applyBlocking()
  })
}

module.exports = sitesRoutes
