'use strict'
const { getDB } = require('../services/db.service')

async function reportsRoutes(fastify, options) {

  // ── Resumen general ───────────────────────────────────────────────────────
  fastify.get('/api/reports/summary', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const db = getDB()
    const { from, to } = req.query
    const fromTs = from ? Math.floor(new Date(from).getTime()/1000) : Math.floor(Date.now()/1000) - 86400*30
    const toTs = to ? Math.floor(new Date(to).getTime()/1000) : Math.floor(Date.now()/1000)

    const totalRx = db.prepare(`SELECT COALESCE(SUM(rx_delta),0) as v FROM traffic_samples WHERE sampled_at BETWEEN ? AND ?`).get(fromTs, toTs)
    const totalTx = db.prepare(`SELECT COALESCE(SUM(tx_delta),0) as v FROM traffic_samples WHERE sampled_at BETWEEN ? AND ?`).get(fromTs, toTs)
    const totalAttacks = db.prepare(`SELECT COUNT(*) as v FROM attack_log WHERE detected_at BETWEEN ? AND ?`).get(fromTs, toTs)
    const uniqueAttackers = db.prepare(`SELECT COUNT(DISTINCT src_ip) as v FROM attack_log WHERE detected_at BETWEEN ? AND ?`).get(fromTs, toTs)
    const panelAccess = db.prepare(`SELECT COUNT(*) as v FROM panel_access_log WHERE accessed_at BETWEEN ? AND ?`).get(fromTs, toTs)
    const topDomain = db.prepare(`SELECT domain, COUNT(*) as c FROM dns_queries WHERE queried_at BETWEEN ? AND ? GROUP BY domain ORDER BY c DESC LIMIT 1`).get(fromTs, toTs)

    return {
      period: { from: new Date(fromTs*1000).toISOString(), to: new Date(toTs*1000).toISOString() },
      traffic: { totalRxBytes: totalRx.v, totalTxBytes: totalTx.v },
      attacks: { total: totalAttacks.v, uniqueAttackers: uniqueAttackers.v },
      panelAccess: panelAccess.v,
      topDomain: topDomain?.domain || null
    }
  })

  // ── Tráfico por interfaz ──────────────────────────────────────────────────
  fastify.get('/api/reports/traffic', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const db = getDB()
    const { from, to, iface, groupBy = 'hour' } = req.query
    const fromTs = from ? Math.floor(new Date(from).getTime()/1000) : Math.floor(Date.now()/1000) - 86400
    const toTs = to ? Math.floor(new Date(to).getTime()/1000) : Math.floor(Date.now()/1000)

    const divisor = groupBy === 'day' ? 86400 : groupBy === 'hour' ? 3600 : 60

    let query = `
      SELECT interface,
             (sampled_at / ${divisor}) * ${divisor} as period,
             SUM(rx_delta) as rx_bytes,
             SUM(tx_delta) as tx_bytes
      FROM traffic_samples
      WHERE sampled_at BETWEEN ? AND ?`
    const params = [fromTs, toTs]

    if (iface) { query += ` AND interface = ?`; params.push(iface) }
    query += ` GROUP BY interface, period ORDER BY period ASC`

    const rows = db.prepare(query).all(...params)
    return { traffic: rows }
  })

  // ── Top interfaces por consumo ────────────────────────────────────────────
  fastify.get('/api/reports/traffic/top-interfaces', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const db = getDB()
    const { from, to } = req.query
    const fromTs = from ? Math.floor(new Date(from).getTime()/1000) : Math.floor(Date.now()/1000) - 86400*7
    const toTs = to ? Math.floor(new Date(to).getTime()/1000) : Math.floor(Date.now()/1000)

    const rows = db.prepare(`
      SELECT interface, SUM(rx_delta) as rx_bytes, SUM(tx_delta) as tx_bytes,
             SUM(rx_delta + tx_delta) as total_bytes
      FROM traffic_samples WHERE sampled_at BETWEEN ? AND ?
      GROUP BY interface ORDER BY total_bytes DESC
    `).all(fromTs, toTs)
    return { interfaces: rows }
  })

  // ── Ataques por país ──────────────────────────────────────────────────────
  fastify.get('/api/reports/attacks/by-country', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const db = getDB()
    const { from, to, limit = 15 } = req.query
    const fromTs = from ? Math.floor(new Date(from).getTime()/1000) : Math.floor(Date.now()/1000) - 86400*30
    const toTs = to ? Math.floor(new Date(to).getTime()/1000) : Math.floor(Date.now()/1000)

    const rows = db.prepare(`
      SELECT country, country_code, COUNT(*) as total, COUNT(DISTINCT src_ip) as unique_ips
      FROM attack_log WHERE detected_at BETWEEN ? AND ? AND country IS NOT NULL
      GROUP BY country_code ORDER BY total DESC LIMIT ?
    `).all(fromTs, toTs, parseInt(limit))
    return { countries: rows }
  })

  // ── Top IPs atacantes ─────────────────────────────────────────────────────
  fastify.get('/api/reports/attacks/top-ips', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const db = getDB()
    const { from, to, limit = 20 } = req.query
    const fromTs = from ? Math.floor(new Date(from).getTime()/1000) : Math.floor(Date.now()/1000) - 86400*30
    const toTs = to ? Math.floor(new Date(to).getTime()/1000) : Math.floor(Date.now()/1000)

    const rows = db.prepare(`
      SELECT src_ip, country, country_code, isp, COUNT(*) as total,
             MAX(detected_at) as last_seen
      FROM attack_log WHERE detected_at BETWEEN ? AND ?
      GROUP BY src_ip ORDER BY total DESC LIMIT ?
    `).all(fromTs, toTs, parseInt(limit))
    return { ips: rows }
  })

  // Borra el historial completo de ataques registrado para Reportes (independiente
  // del log operativo de Suricata en /var/log/suricata/eve.json, que se limpia aparte).
  fastify.post('/api/reports/attacks/clear', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    try {
      const db = getDB()
      const before = db.prepare('SELECT COUNT(*) as n FROM attack_log').get().n
      db.prepare('DELETE FROM attack_log').run()
      return { success: true, deleted: before }
    } catch(e) {
      return reply.code(500).send({ success: false, error: e.message })
    }
  })

  // Conteo total liviano, para el badge del dashboard (evita escanear/agrupar toda la tabla)
  fastify.get('/api/reports/attacks/count', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const db = getDB()
    const total = db.prepare('SELECT COUNT(*) as n FROM attack_log').get().n
    return { total }
  })

  // ── Lista de alertas para el modulo Suricata > Alertas (paginada, con agrupacion por IP) ──
  fastify.get('/api/reports/attacks/list', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const db = getDB()
    const { threatKey, groupByIp, limit = 25, offset = 0 } = req.query
    const lim = Math.min(parseInt(limit) || 25, 100)
    const off = parseInt(offset) || 0

    if (groupByIp === 'true' && (!threatKey || threatKey === 'all')) {
      // Vista "Todas": agrupamos por IP de origen, mostrando cuantos eventos y de que tipos
      const totalRow = db.prepare('SELECT COUNT(DISTINCT src_ip) as n FROM attack_log').get()
      const rows = db.prepare(`
        SELECT src_ip, country, country_code, city, isp,
               COUNT(*) as total,
               MAX(detected_at) as last_seen,
               GROUP_CONCAT(DISTINCT threat_icon || ' ' || threat_label) as types
        FROM attack_log
        GROUP BY src_ip
        ORDER BY last_seen DESC
        LIMIT ? OFFSET ?
      `).all(lim, off)
      return { grouped: true, total: totalRow.n, rows }
    }

    // Vista filtrada por tipo especifico: lista plana de eventos individuales
    let query = 'SELECT * FROM attack_log'
    let countQuery = 'SELECT COUNT(*) as n FROM attack_log'
    const params = []
    if (threatKey && threatKey !== 'all') {
      query += ' WHERE threat_key = ?'
      countQuery += ' WHERE threat_key = ?'
      params.push(threatKey)
    }
    const totalRow = db.prepare(countQuery).get(...params)
    query += ' ORDER BY detected_at DESC LIMIT ? OFFSET ?'
    const rows = db.prepare(query).all(...params, lim, off)
    return { grouped: false, total: totalRow.n, rows }
  })

  // ── Detalle de una IP especifica: geo + lista de sus eventos ────────────────
  fastify.get('/api/reports/attacks/by-ip/:ip', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const db = getDB()
    const ip = req.params.ip
    const rows = db.prepare(`
      SELECT * FROM attack_log WHERE src_ip = ? ORDER BY detected_at DESC LIMIT 100
    `).all(ip)
    if (rows.length === 0) return { ip, events: [] }
    const first = rows[0]
    return {
      ip,
      country: first.country, countryCode: first.country_code,
      city: first.city, isp: first.isp,
      totalEvents: rows.length,
      events: rows
    }
  })

  fastify.get('/api/reports/attacks/by-type', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const db = getDB()
    const { from, to } = req.query
    const fromTs = from ? Math.floor(new Date(from).getTime()/1000) : Math.floor(Date.now()/1000) - 86400*30
    const toTs = to ? Math.floor(new Date(to).getTime()/1000) : Math.floor(Date.now()/1000)
    // Agrupamos por threat_key (nuestra taxonomia), con fallback al attack_type crudo
    // para registros viejos guardados antes de esta mejora.
    const rows = db.prepare(`
      SELECT
        COALESCE(threat_key, 'other') as threat_key,
        COALESCE(threat_label, attack_type, 'Sin clasificar') as threat_label,
        COALESCE(threat_icon, '❓') as threat_icon,
        COUNT(*) as total
      FROM attack_log WHERE detected_at BETWEEN ? AND ?
      GROUP BY threat_key ORDER BY total DESC LIMIT 20
    `).all(fromTs, toTs)
    return { types: rows }
  })

  // ── Detalle de ataques (para hacer click en un tipo y ver cada evento) ────
  fastify.get('/api/reports/attacks/detail', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const db = getDB()
    const { from, to, threatKey, limit = 200 } = req.query
    const fromTs = from ? Math.floor(new Date(from).getTime()/1000) : Math.floor(Date.now()/1000) - 86400*30
    const toTs = to ? Math.floor(new Date(to).getTime()/1000) : Math.floor(Date.now()/1000)
    let query = `
      SELECT id, src_ip, country, country_code, city, isp,
             attack_type, threat_key, threat_label, threat_icon,
             severity, signature, proto, dest_port, blocked, detected_at
      FROM attack_log WHERE detected_at BETWEEN ? AND ?
    `
    const params = [fromTs, toTs]
    if (threatKey && threatKey !== 'all') {
      query += ' AND threat_key = ?'
      params.push(threatKey)
    }
    query += ' ORDER BY detected_at DESC LIMIT ?'
    params.push(parseInt(limit))
    const rows = db.prepare(query).all(...params)
    return { events: rows }
  })
  // ── Tipos de ataques ──────────────────────────────────────────────────────

  // ── Top dominios DNS ──────────────────────────────────────────────────────
  fastify.get('/api/reports/dns/top-domains', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const db = getDB()
    const { from, to, limit = 20 } = req.query
    const fromTs = from ? Math.floor(new Date(from).getTime()/1000) : Math.floor(Date.now()/1000) - 86400*7
    const toTs = to ? Math.floor(new Date(to).getTime()/1000) : Math.floor(Date.now()/1000)

    const rows = db.prepare(`
      SELECT domain, COUNT(*) as queries, COUNT(DISTINCT client_ip) as unique_clients
      FROM dns_queries WHERE queried_at BETWEEN ? AND ?
      GROUP BY domain ORDER BY queries DESC LIMIT ?
    `).all(fromTs, toTs, parseInt(limit))
    return { domains: rows }
  })

  // ── Accesos al panel ──────────────────────────────────────────────────────
  fastify.get('/api/reports/panel/access', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const db = getDB()
    const { from, to, limit = 100 } = req.query
    const fromTs = from ? Math.floor(new Date(from).getTime()/1000) : Math.floor(Date.now()/1000) - 86400*7
    const toTs = to ? Math.floor(new Date(to).getTime()/1000) : Math.floor(Date.now()/1000)

    const rows = db.prepare(`
      SELECT username, ip, method, endpoint, status_code, response_time, accessed_at
      FROM panel_access_log WHERE accessed_at BETWEEN ? AND ?
      ORDER BY accessed_at DESC LIMIT ?
    `).all(fromTs, toTs, parseInt(limit))
    return { logs: rows }
  })

  // ── Timeline de ataques ───────────────────────────────────────────────────
  fastify.get('/api/reports/attacks/timeline', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const db = getDB()
    const { from, to, groupBy = 'hour' } = req.query
    const fromTs = from ? Math.floor(new Date(from).getTime()/1000) : Math.floor(Date.now()/1000) - 86400*7
    const toTs = to ? Math.floor(new Date(to).getTime()/1000) : Math.floor(Date.now()/1000)
    const divisor = groupBy === 'day' ? 86400 : 3600

    const rows = db.prepare(`
      SELECT (detected_at / ${divisor}) * ${divisor} as period, COUNT(*) as total
      FROM attack_log WHERE detected_at BETWEEN ? AND ?
      GROUP BY period ORDER BY period ASC
    `).all(fromTs, toTs)
    return { timeline: rows }
  })

}

module.exports = reportsRoutes
