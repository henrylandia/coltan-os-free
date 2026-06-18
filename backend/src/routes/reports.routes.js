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

  // ── Tipos de ataques ──────────────────────────────────────────────────────
  fastify.get('/api/reports/attacks/by-type', { onRequest: [fastify.authenticate] }, async (req, reply) => {
    const db = getDB()
    const { from, to } = req.query
    const fromTs = from ? Math.floor(new Date(from).getTime()/1000) : Math.floor(Date.now()/1000) - 86400*30
    const toTs = to ? Math.floor(new Date(to).getTime()/1000) : Math.floor(Date.now()/1000)

    const rows = db.prepare(`
      SELECT attack_type, COUNT(*) as total
      FROM attack_log WHERE detected_at BETWEEN ? AND ? AND attack_type IS NOT NULL
      GROUP BY attack_type ORDER BY total DESC LIMIT 20
    `).all(fromTs, toTs)
    return { types: rows }
  })

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
