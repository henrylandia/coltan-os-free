'use strict'

const {
  getErrors, clearErrors, getReportingSettings, updateReportingSettings, reportError
} = require('../services/error-reporting.service')

async function errorReportingRoutes(fastify, options) {

  fastify.get('/api/diagnostics/errors', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const { source, since } = req.query
    const errors = await getErrors({ source, since })
    return { errors, total: errors.length }
  })

  fastify.delete('/api/diagnostics/errors', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await clearErrors()
  })

  fastify.get('/api/diagnostics/settings', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await getReportingSettings()
  })

  fastify.post('/api/diagnostics/settings', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    return await updateReportingSettings(req.body)
  })

  // Endpoint para que otros servicios (dhcp, suricata, wireguard, etc) reporten errores manualmente
  fastify.post('/api/diagnostics/report', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const { source, message, stack, context } = req.body
    reportError(source || 'manual', message, stack, context)
    return { success: true }
  })
}

module.exports = errorReportingRoutes
