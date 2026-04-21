'use strict'

const bcrypt = require('bcrypt')
const config = require('../config')

// In-memory users for now (Phase 1)
// In future phases this will be replaced with a database
const users = []

// Create default admin on startup
async function initDefaultAdmin() {
  const hash = await bcrypt.hash(config.DEFAULT_ADMIN_PASS, 10)
  users.push({
    id: 1,
    username: config.DEFAULT_ADMIN_USER,
    password: hash,
    role: 'admin'
  })
  console.log(`Default admin created: ${config.DEFAULT_ADMIN_USER}`)
}

async function findUser(username) {
  return users.find(u => u.username === username) || null
}

async function validatePassword(plain, hash) {
  return bcrypt.compare(plain, hash)
}

module.exports = { initDefaultAdmin, findUser, validatePassword }
