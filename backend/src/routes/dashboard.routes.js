'use strict'
const { getAllMetrics } = require('../services/metrics.service')
const { getStatus: getFirewallStatus } = require('../services/firewall.service')
const { getPools } = require('../services/zfs.service')
const { getPolicies, getSnapshots } = require('../services/backup.service')

async function dashboardRoutes(fastify, options) {
  fastify.get('/api/dashboard', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    const [metrics, firewall, pools, policies, snapshots] = await Promise.all([
      getAllMetrics(),
      getFirewallStatus(),
      getPools(),
      getPolicies(),
      getSnapshots()
    ])
    const failedPolicies = policies.filter(p => p.lastStatus === 'error')
    const poolHealth = pools.every(p => p.health === 'ONLINE') ? 'healthy' : 'degraded'
    return {
      metrics,
      modules: {
        firewall: {
          enabled: firewall.enabled,
          states: firewall.states,
          status: firewall.enabled ? 'online' : 'disabled'
        },
        backup: {
          totalPolicies: policies.length,
          activePolicies: policies.filter(p => p.enabled).length,
          failedPolicies: failedPolicies.length,
          status: failedPolicies.length > 0 ? 'warning' : policies.length === 0 ? 'none' : 'ok',
          poolHealth,
          totalSnapshots: snapshots.length
        }
      }
    }
  })
}
module.exports = dashboardRoutes
