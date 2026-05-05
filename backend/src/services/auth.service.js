'use strict'
const bcrypt = require('bcrypt')
const fs = require('fs')
const config = require('../config')

const USERS_FILE = '/usr/local/etc/coltan/users.json'

async function loadUsers() {
  try {
    const content = fs.readFileSync(USERS_FILE, 'utf8')
    return JSON.parse(content)
  } catch(e) { return [] }
}

async function saveUsers(users) {
  fs.mkdirSync('/usr/local/etc/coltan', { recursive: true })
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2))
}

async function initDefaultAdmin() {
  const users = await loadUsers()
  if (users.find(u => u.username === config.DEFAULT_ADMIN_USER)) {
    console.log('Admin user loaded from file')
    return
  }
  const hash = await bcrypt.hash(config.DEFAULT_ADMIN_PASS, 10)
  users.push({ id: 1, username: config.DEFAULT_ADMIN_USER, password: hash, role: 'admin' })
  await saveUsers(users)
  console.log(`Default admin created: ${config.DEFAULT_ADMIN_USER}`)
}

async function findUser(username) {
  const users = await loadUsers()
  return users.find(u => u.username === username) || null
}

async function validatePassword(plain, hash) {
  return bcrypt.compare(plain, hash)
}

async function changePassword(username, newPassword) {
  const users = await loadUsers()
  const user = users.find(u => u.username === username)
  if (!user) return false
  user.password = await bcrypt.hash(newPassword, 10)
  await saveUsers(users)
  return true
}

module.exports = { initDefaultAdmin, findUser, validatePassword, changePassword }
