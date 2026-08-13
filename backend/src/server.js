'use strict'
const fastify = require('fastify')({ logger: true })
const path = require('path')
const fs = require('fs')
const config = require('./config')
const { initDefaultAdmin } = require('./services/auth.service')

// Helper: solo registra una ruta si el archivo existe fisicamente en disco.
// Los modulos premium solo existen tras un upgrade legitimo via clave SSH del repo privado.
function registerIfExists(fastifyInstance, relPath) {
  const fullPath = path.join(__dirname, relPath.replace('./', '') + '.js')
  if (fs.existsSync(fullPath)) {
    fastifyInstance.register(require(relPath))
    return true
  }
  return false
}

// Helper: require condicional de un service, devuelve null si no existe
function requireIfExists(relPath) {
  const fullPath = path.join(__dirname, relPath.replace('./', '') + '.js')
  if (fs.existsSync(fullPath)) return require(relPath)
  return null
}

// Plugins
fastify.register(require('@fastify/formbody'))
// Handle empty JSON body gracefully
fastify.addHook('preValidation', async (request, reply) => {
  if (!request.body && (request.method === 'DELETE' || request.method === 'POST' || request.method === 'PUT')) {
    request.body = {}
  }
})
// JWT plugin
fastify.register(require('@fastify/jwt'), {
  secret: config.JWT_SECRET,
  sign: { expiresIn: config.JWT_EXPIRES }
})
// Authenticate decorator
fastify.decorate('authenticate', async function(request, reply) {
  try {
    await request.jwtVerify()
  } catch (err) {
    reply.code(401).send({ error: 'Unauthorized' })
  }
})
// License middleware - bloquea endpoints premium sin licencia (valida contra sistema.coltanos.com)
const { licenseMiddleware } = require('./middleware/license')
fastify.addHook('onRequest', licenseMiddleware)

// Panel access log hook (analytics - solo si collectors.service existe, es decir, Premium)
fastify.addHook('onResponse', async (request, reply) => {
  try {
    const collectors = requireIfExists('./services/collectors.service')
    if (!collectors) return
    const user = request.user?.username || null
    const ip = request.headers['x-forwarded-for'] || request.ip
    if (request.url.startsWith('/api/')) {
      collectors.logPanelAccess(user, ip, request.method, request.url, reply.statusCode, reply.elapsedTime)
    }
  } catch(e) {}
})

// Serve frontend
fastify.register(require('@fastify/static'), {
  root: path.join(__dirname, '../../frontend/public'),
  prefix: '/'
})

// ── Rutas siempre presentes (FREE + PREMIUM) ────────────────────────────────
fastify.register(require('./routes/auth.routes'))
fastify.register(require('./routes/metrics.routes'))
fastify.register(require('./routes/network.routes'))
fastify.register(require('./routes/firewall.routes'))
fastify.register(require('./routes/zfs.routes'))
fastify.register(require('./routes/backup.routes'))
fastify.register(require('./routes/settings.routes'))
fastify.register(require('./routes/dashboard.routes'))
fastify.register(require('./routes/dhcp.routes'))
fastify.register(require('./routes/interfaces.routes'))
fastify.register(require('./routes/wireguard.routes'))
fastify.register(require('./routes/openvpn.routes'))
fastify.register(require('./routes/suricata.routes'))
fastify.register(require('./routes/vlans.routes'))
fastify.register(require('./routes/multiwan.routes'))
fastify.register(require('./routes/error-reporting.routes'))
fastify.register(require('./routes/config-backup.routes'))

// ── Rutas exclusivas PREMIUM — se registran solo si el archivo existe ──────
// (llegan al disco unicamente via upgrade.service.js con licencia activa)
registerIfExists(fastify, './routes/sites.routes')
registerIfExists(fastify, './routes/security.routes')
registerIfExists(fastify, './routes/qos.routes')
registerIfExists(fastify, './routes/reports.routes')

// WebSockets
fastify.register(require('@fastify/websocket'))
fastify.register(require('./routes/ws.routes'))

// Public health
fastify.get('/api/health', async (request, reply) => {
  return {
    status: 'ok',
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  }
})
// Protected routes
fastify.register(async function(fastify) {
  fastify.addHook('onRequest', fastify.authenticate)
  fastify.get('/api/status', async (request, reply) => {
    return {
      name: 'Coltan OS',
      version: '0.1.0',
      status: 'online',
      user: request.user.username
    }
  })
})

// Inicializar captura global de errores no manejados
require('./services/error-reporting.service').initGlobalHandlers()

const start = async () => {
  try {
    await initDefaultAdmin()
    await fastify.listen({ port: config.PORT, host: config.HOST })
    console.log(`Coltan OS running on port ${config.PORT}`)

    // Restore VLANs after reboot (FREE + PREMIUM)
    const { restoreVLANs } = require('./services/vlans.service')
    try { const r = await restoreVLANs(); console.log('[VLANs] Restored:', r.restored) } catch(e) {}

    // ── Funcionalidad PREMIUM — solo si el archivo existe ─────────────────
    const sitesService = requireIfExists('./services/sites.service')
    if (sitesService) {
      setInterval(async () => {
        try {
          const result = await sitesService.refreshDNS()
          console.log('[Sites] DNS refresh:', result.updated, 'domains updated')
        } catch(e) {}
      }, 60 * 60 * 1000) // cada hora
    }

    const qosService = requireIfExists('./services/qos.service')
    if (qosService) {
      try { await qosService.restoreQoS(); console.log('[QoS] Rules restored') } catch(e) {}
    }

    // Captive portal session cleanup (FREE + PREMIUM, si existe)
    const captiveService = requireIfExists('./services/captive.service')
    if (captiveService) {
      setInterval(async () => {
        try { await captiveService.cleanExpiredSessions() } catch(e) {}
      }, 60 * 1000)
    }

    // Suricata auto-block watcher (FREE + PREMIUM)
    const { startWatcher } = require('./services/suricata-autoblock')
    startWatcher()

    // Heartbeat hacia sistema.coltanos.com (FREE + PREMIUM — valida licencia siempre)
    const { startHeartbeat } = require('./services/heartbeat.service')
    startHeartbeat()

    // MultiWAN monitor (FREE + PREMIUM)
    const { startMonitor } = require('./services/multiwan.service')
    startMonitor()

    // Analytics collectors — exclusivo PREMIUM
    const collectorsService = requireIfExists('./services/collectors.service')
    if (collectorsService) {
      collectorsService.startCollectors()
    }
  } catch (err) {
    fastify.log.error(err)
    process.exit(1)
  }
}
start()
