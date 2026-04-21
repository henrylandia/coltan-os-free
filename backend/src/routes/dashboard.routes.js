'use strict'

const { getAllMetrics } = require('../services/metrics.service')
const { getStatus: getFirewallStatus } = require('../services/firewall.service')
const { getStatus: getSambaStatus } = require('../services/samba.service')
const { getPools } = require('../services/zfs.service')
const { getPolicies, getSnapshots } = require('../services/backup.service')

async function dashboardRoutes(fastify, options) {

  fastify.get('/api/dashboard', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    const [metrics, firewall, samba, pools, policies, snapshots] = await Promise.all([
      getAllMetrics(),
      getFirewallStatus(),
      getSambaStatus(),
      getPools(),
      getPolicies(),
      getSnapshots()
    ])

    // Check if any backup policy failed
    const failedPolicies = policies.filter(p => p.lastStatus === 'error')
    const pendingPolicies = policies.filter(p => p.lastStatus === null && p.enabled)

    // Pool health
    const poolHealth = pools.every(p => p.health === 'ONLINE') ? 'healthy' : 'degraded'
    const totalPools = pools.length
    const totalSnapshots = snapshots.length

    return {
      metrics,
      modules: {
        firewall: {
          enabled: firewall.enabled,
          states: firewall.states,
          status: firewall.enabled ? 'online' : 'disabled'
        },
        fileserver: {
          status: samba.running ? 'online' : 'offline',
          poolHealth,
          totalPools,
          totalSnapshots
        },
        backup: {
          totalPolicies: policies.length,
          activePolicies: policies.filter(p => p.enabled).length,
          failedPolicies: failedPolicies.length,
          status: failedPolicies.length > 0 ? 'warning' : policies.length === 0 ? 'none' : 'ok'
        }
      }
    }
  })

}

module.exports = dashboardRoutes
