'use strict'

const fs = require('fs')
const https = require('https')
const http = require('http')

const SETTINGS_FILE = '/usr/local/etc/coltan/error-reporting.json'
const ERRORS_LOG_FILE = '/var/log/coltan-errors.json'
const REPORT_ENDPOINT_HOST = 'sistema.coltanos.com'
const REPORT_ENDPOINT_PATH = '/api/error-reports'
const MAX_LOCAL_ERRORS = 500
const MAX_QUEUE_PER_MINUTE = 20

let sentThisMinute = 0
let queueResetInterval = null

function getSettings() {
  try {
    return JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8'))
  } catch(e) {
    // Por defecto ON, pero configurable — NO hardcodeado en el código, vive en config
    return { enabled: true }
  }
}

function saveSettings(settings) {
  fs.writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2))
}

function getLocalErrors() {
  try {
    return JSON.parse(fs.readFileSync(ERRORS_LOG_FILE, 'utf8'))
  } catch(e) { return [] }
}

function saveLocalErrors(errors) {
  try {
    // Mantener solo los ultimos MAX_LOCAL_ERRORS
    const trimmed = errors.slice(-MAX_LOCAL_ERRORS)
    fs.writeFileSync(ERRORS_LOG_FILE, JSON.stringify(trimmed, null, 2))
  } catch(e) {}
}

function getSystemInfo() {
  let hostname = 'unknown'
  let version = 'unknown'
  let licenseStatus = 'unknown'
  try { hostname = require('os').hostname() } catch(e) {}
  try {
    const pkg = JSON.parse(fs.readFileSync('/opt/coltanos/backend/package.json', 'utf8'))
    version = pkg.version
  } catch(e) {}
  try {
    const lic = JSON.parse(fs.readFileSync('/usr/local/etc/coltan/license-status.json', 'utf8'))
    licenseStatus = lic.licenseStatus || 'unknown'
  } catch(e) {}
  return { hostname, version, licenseStatus }
}

function sendToServer(errorEntry) {
  const settings = getSettings()
  if (!settings.enabled) return

  // Rate limiting simple
  if (sentThisMinute >= MAX_QUEUE_PER_MINUTE) return
  sentThisMinute++

  const sysInfo = getSystemInfo()
  const payload = JSON.stringify({
    ...errorEntry,
    hostname: sysInfo.hostname,
    coltanVersion: sysInfo.version,
    licenseStatus: sysInfo.licenseStatus,
  })

  const options = {
    hostname: REPORT_ENDPOINT_HOST,
    path: REPORT_ENDPOINT_PATH,
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
    timeout: 5000
  }

  try {
    const req = https.request(options, (res) => { res.on('data', () => {}) })
    req.on('error', () => {}) // Fallo silencioso — nunca romper el sistema por esto
    req.on('timeout', () => req.destroy())
    req.write(payload)
    req.end()
  } catch(e) {}
}

// Sanitiza el error para no incluir datos sensibles (contraseñas, tokens, IPs de LAN, etc)
function sanitize(text) {
  if (!text) return ''
  return String(text)
    .replace(/password["\s:=]+["']?[^"'\s,}]+/gi, 'password=[REDACTED]')
    .replace(/token["\s:=]+["']?[^"'\s,}]+/gi, 'token=[REDACTED]')
    .replace(/privateKey["\s:=]+["']?[^"'\s,}]+/gi, 'privateKey=[REDACTED]')
    .replace(/\b(19[2-9]|10|172)\.\d+\.\d+\.\d+\b/g, '[IP_LAN]') // oculta IPs privadas de la LAN del cliente
}

function reportError(source, message, stack, context) {
  try {
    const entry = {
      id: Date.now().toString() + Math.random().toString(36).slice(2, 7),
      timestamp: new Date().toISOString(),
      source,                          // 'backend' | 'install' | 'service:kea' | 'service:suricata' etc.
      message: sanitize(message),
      stack: sanitize(stack || ''),
      context: sanitize(JSON.stringify(context || {})),
    }

    const errors = getLocalErrors()
    errors.push(entry)
    saveLocalErrors(errors)

    sendToServer(entry)
  } catch(e) {
    // Nunca dejar que el sistema de reporte de errores rompa algo
  }
}

function initGlobalHandlers() {
  process.on('uncaughtException', (err) => {
    reportError('backend:uncaughtException', err.message, err.stack)
  })
  process.on('unhandledRejection', (reason) => {
    const msg = reason instanceof Error ? reason.message : String(reason)
    const stack = reason instanceof Error ? reason.stack : ''
    reportError('backend:unhandledRejection', msg, stack)
  })

  if (!queueResetInterval) {
    queueResetInterval = setInterval(() => { sentThisMinute = 0 }, 60 * 1000)
  }
}

async function getErrors(filters = {}) {
  let errors = getLocalErrors()
  if (filters.source) errors = errors.filter(e => e.source.includes(filters.source))
  if (filters.since) errors = errors.filter(e => new Date(e.timestamp) >= new Date(filters.since))
  return errors.slice().reverse() // mas reciente primero
}

async function clearErrors() {
  saveLocalErrors([])
  return { success: true }
}

async function getReportingSettings() {
  return getSettings()
}

async function updateReportingSettings(updates) {
  const current = getSettings()
  const merged = { ...current, ...updates }
  saveSettings(merged)
  return { success: true, settings: merged }
}

module.exports = {
  reportError, initGlobalHandlers, getErrors, clearErrors,
  getReportingSettings, updateReportingSettings
}
