'use strict'

const pty = require('node-pty')

async function consoleRoutes(fastify, options) {

  fastify.get('/ws/console', { websocket: true }, (socket, req) => {
    console.log('Console WebSocket connected')

    // Spawn a shell
    const shell = pty.spawn('/bin/sh', [], {
      name: 'xterm-256color',
      cols: 80,
      rows: 24,
      cwd: '/root',
      env: process.env
    })

    // Send shell output to browser
    shell.onData(data => {
      if (socket.readyState === 1) {
        socket.send(JSON.stringify({ type: 'output', data }))
      }
    })

    shell.onExit(({ exitCode }) => {
      if (socket.readyState === 1) {
        socket.send(JSON.stringify({ type: 'exit', code: exitCode }))
      }
      socket.close()
    })

    // Receive input from browser
    socket.on('message', (msg) => {
      try {
        const parsed = JSON.parse(msg)
        if (parsed.type === 'input') {
          shell.write(parsed.data)
        } else if (parsed.type === 'resize') {
          shell.resize(parsed.cols, parsed.rows)
        }
      } catch(e) {}
    })

    socket.on('close', () => {
      console.log('Console WebSocket disconnected')
      try { shell.kill() } catch(e) {}
    })

    socket.on('error', () => {
      try { shell.kill() } catch(e) {}
    })
  })

}

module.exports = consoleRoutes
