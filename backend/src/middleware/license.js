'use strict'
const fs = require('fs')

const LICENSE_STATUS_FILE = '/usr/local/etc/coltan/license-status.json'

const PREMIUM_ENDPOINTS = [
  { method: 'POST', path: /^\/api\/suricata\// },
  { method: 'PUT', path: /^\/api\/suricata\// },
  { method: 'DELETE', path: /^\/api\/suricata\// },
  { method: 'ANY', path: /^\/api\/security\/unbound/ },
  { method: 'ANY', path: /^\/api\/qos\// },
  { method: 'POST', path: /^\/api\/sites\// },
  { method: 'PUT', path: /^\/api\/sites\// },
  { method: 'DELETE', path: /^\/api\/sites\// },
  { method: 'ANY', path: /^\/api\/reports\// },
  { method: 'POST', path: /^\/api\/settings\/coltan\/update/ },
]

const SURICATA_FREE = [
  '/api/suricata/status',
  '/api/suricata/alerts',
  '/api/suricata/stats',
]

function getLicenseStatus() {
  try {
    return JSON.parse(fs.readFileSync(LICENSE_STATUS_FILE, 'utf8'))
  } catch(e) {
    return { active: false, licenseStatus: 'no_license' }
  }
}

function isPremiumEndpoint(method, url) {
  if (method === 'GET' && SURICATA_FREE.some(e => url.startsWith(e))) return false
  for (const rule of PREMIUM_ENDPOINTS) {
    const methodMatch = rule.method === 'ANY' || rule.method === method
    const pathMatch = rule.path.test(url)
    if (methodMatch && pathMatch) return true
  }
  return false
}

function licenseMiddleware(request, reply, done) {
  const url = request.url.split('?')[0]
  const method = request.method

  if (!isPremiumEndpoint(method, url)) {
    done()
    return
  }

  const status = getLicenseStatus()
  if (!status.active) {
    reply.code(403).send({
      error: 'Licencia premium requerida',
      feature: 'premium',
      licenseStatus: status.licenseStatus || 'no_license',
      message: 'Esta función requiere una licencia activa de Coltan OS Premium. Activá tu licencia en Settings → Licencia.'
    })
    return
  }

  done()
}

module.exports = { licenseMiddleware, getLicenseStatus, isPremiumEndpoint }
