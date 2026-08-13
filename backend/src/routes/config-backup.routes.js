'use strict'

const {
  createBackup, listBackups, getBackupContent, deleteBackup,
  getRestorePreview, restoreBackup,
  getPolicy, savePolicy
} = require('../services/config-backup.service')

async function configBackupRoutes(fastify, options) {

  fastify.get('/api/config-backup/list', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return { backups: await listBackups() }
  })

  fastify.post('/api/config-backup/create', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const { encryptPassword } = req.body || {}
    return await createBackup('manual', encryptPassword || null)
  })

  // Sin fastify.authenticate estandar porque el link de descarga (<a href>) no puede mandar headers.
  // Verificamos el JWT manualmente desde el query param ?token=
  fastify.get('/api/config-backup/download/:filename', async (req, reply) => {
    const token = req.query.token
    if (!token) return reply.code(401).send({ error: 'Token requerido' })
    try {
      fastify.jwt.verify(token)
    } catch(e) {
      return reply.code(401).send({ error: 'Token invalido' })
    }
    try {
      const content = await getBackupContent(req.params.filename)
      reply.header('Content-Type', 'application/json')
      reply.header('Content-Disposition', `attachment; filename="${req.params.filename}"`)
      return content
    } catch(e) {
      return reply.code(404).send({ error: 'Backup no encontrado' })
    }
  })

  fastify.delete('/api/config-backup/:filename', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    try {
      return await deleteBackup(req.params.filename)
    } catch(e) {
      return reply.code(404).send({ error: 'Backup no encontrado' })
    }
  })

  // Preview del restore: subir un JSON de backup y ver que interfaces necesitan mapeo
  fastify.post('/api/config-backup/restore-preview', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const { snapshot, password } = req.body
    if (!snapshot) return reply.code(400).send({ error: 'snapshot requerido' })
    return await getRestorePreview(snapshot, password || null)
  })

  // Aplicar el restore con el mapeo de interfaces elegido por el usuario
  fastify.post('/api/config-backup/restore', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const { snapshot, interfaceMapping, password } = req.body
    if (!snapshot) return reply.code(400).send({ error: 'snapshot requerido' })
    return await restoreBackup(snapshot, interfaceMapping || {}, password || null)
  })

  // Restaurar directamente desde un backup ya guardado localmente (por filename)
  fastify.post('/api/config-backup/restore-local/:filename', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    try {
      const content = await getBackupContent(req.params.filename)
      const { interfaceMapping, password } = req.body
      return await restoreBackup(content, interfaceMapping || {}, password || null)
    } catch(e) {
      return reply.code(404).send({ error: 'Backup no encontrado' })
    }
  })

  fastify.post('/api/config-backup/restore-local-preview/:filename', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    try {
      const content = await getBackupContent(req.params.filename)
      const { password } = req.body || {}
      return await getRestorePreview(content, password || null)
    } catch(e) {
      return reply.code(404).send({ error: 'Backup no encontrado' })
    }
  })

  fastify.get('/api/config-backup/policy', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await getPolicy()
  })

  fastify.post('/api/config-backup/policy', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await savePolicy(req.body)
  })
}

module.exports = configBackupRoutes
