'use strict'

const { getAllMetrics } = require('../services/metrics.service')

async function wsRoutes(fastify, options) {

  fastify.get('/ws/metrics', { websocket: true }, (socket, req) => {
    console.log('WebSocket client connected')

    // Send metrics immediately on connect
    async function sendMetrics() {
      try {
        const metrics = await getAllMetrics()
        if (socket.readyState === 1) {
          socket.send(JSON.stringify({ type: 'metrics', data: metrics }))
        }
      } catch(e) {
        console.error('Error sending metrics:', e)
      }
    }

    // Send every 3 seconds
    sendMetrics()
    const interval = setInterval(sendMetrics, 3000)

    socket.on('close', () => {
      console.log('WebSocket client disconnected')
      clearInterval(interval)
    })

    socket.on('error', (err) => {
      console.error('WebSocket error:', err)
      clearInterval(interval)
    })
  })

}

module.exports = wsRoutes
