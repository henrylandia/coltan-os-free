'use strict'

const { exec } = require('child_process')
const { promisify } = require('util')
const execAsync = promisify(exec)
const fs = require('fs').promises
const fsSync = require('fs')
const crypto = require('crypto')

const CAPTIVE_DIR = '/usr/local/etc/coltan/captive'
const PORTALS_FILE = `${CAPTIVE_DIR}/portals.json`
const USERS_FILE = `${CAPTIVE_DIR}/users.json`
const GROUPS_FILE = `${CAPTIVE_DIR}/groups.json`
const SESSIONS_FILE = `${CAPTIVE_DIR}/sessions.json`
const NGINX_CONF = '/usr/local/etc/nginx/nginx.conf'
const PORTAL_HTML_DIR = '/opt/coltanos/captive-portal'

async function ensureDir() {
  await execAsync(`mkdir -p ${CAPTIVE_DIR}`)
  await execAsync(`mkdir -p ${PORTAL_HTML_DIR}/templates`)
}

// ─── PORTALS ──────────────────────────────────────────────────────────────────

async function getPortals() {
  try {
    const content = await fs.readFile(PORTALS_FILE, 'utf8')
    return JSON.parse(content)
  } catch(e) { return [] }
}

async function savePortals(portals) {
  await ensureDir()
  await fs.writeFile(PORTALS_FILE, JSON.stringify(portals, null, 2))
}

async function createPortal(data) {
  const portals = await getPortals()
  const portal = {
    id: Date.now().toString(),
    enabled: false,
    name: data.name || 'Portal Cautivo',
    interface: data.interface,           // re1, vlan500, etc
    mode: data.mode || 'public',         // 'public' | 'users' | 'groups'
    groupId: data.groupId || null,
    sessionMinutes: parseInt(data.sessionMinutes) || 60,
    downloadKbps: parseInt(data.downloadKbps) || 0,
    uploadKbps: parseInt(data.uploadKbps) || 0,
    template: data.template || 'default', // 'default' | 'custom' | 'embed'
    customHtml: data.customHtml || '',
    embedCode: data.embedCode || '',
    logoUrl: data.logoUrl || '',
    title: data.title || 'Bienvenido',
    subtitle: data.subtitle || 'Hacé clic para navegar',
    buttonText: data.buttonText || 'Comenzar',
    bgColor: data.bgColor || '#0f1117',
    accentColor: data.accentColor || '#4f8ef7',
    createdAt: new Date().toISOString()
  }
  portals.push(portal)
  await savePortals(portals)
  return { success: true, portal }
}

async function updatePortal(id, data) {
  const portals = await getPortals()
  const idx = portals.findIndex(p => p.id === id)
  if (idx === -1) return { success: false, error: 'Portal not found' }
  portals[idx] = { ...portals[idx], ...data }
  await savePortals(portals)
  // If enabled, regenerate nginx and PF
  if (portals[idx].enabled) await applyPortal(portals[idx])
  return { success: true }
}

async function deletePortal(id) {
  const portals = await getPortals()
  const portal = portals.find(p => p.id === id)
  if (portal && portal.enabled) await disablePortal(portal)
  const filtered = portals.filter(p => p.id !== id)
  await savePortals(filtered)
  return { success: true }
}

async function enablePortal(id) {
  const portals = await getPortals()
  const portal = portals.find(p => p.id === id)
  if (!portal) return { success: false, error: 'Portal not found' }
  portal.enabled = true
  await savePortals(portals)
  await applyPortal(portal)
  return { success: true }
}

async function disablePortalById(id) {
  const portals = await getPortals()
  const portal = portals.find(p => p.id === id)
  if (!portal) return { success: false, error: 'Portal not found' }
  portal.enabled = false
  await savePortals(portals)
  await disablePortal(portal)
  return { success: true }
}

// ─── USERS ────────────────────────────────────────────────────────────────────

async function getUsers() {
  try {
    const content = await fs.readFile(USERS_FILE, 'utf8')
    return JSON.parse(content)
  } catch(e) { return [] }
}

async function createUser(data) {
  const users = await getUsers()
  if (users.find(u => u.username === data.username)) {
    return { success: false, error: 'Usuario ya existe' }
  }
  const hash = crypto.createHash('sha256').update(data.password).digest('hex')
  const user = {
    id: Date.now().toString(),
    username: data.username,
    password: hash,
    groupId: data.groupId || null,
    enabled: true,
    createdAt: new Date().toISOString()
  }
  users.push(user)
  await ensureDir()
  await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2))
  return { success: true, user: { ...user, password: undefined } }
}

async function deleteUser(id) {
  const users = await getUsers()
  const filtered = users.filter(u => u.id !== id)
  await fs.writeFile(USERS_FILE, JSON.stringify(filtered, null, 2))
  return { success: true }
}

async function updateUser(id, data) {
  const users = await getUsers()
  const idx = users.findIndex(u => u.id === id)
  if (idx === -1) return { success: false, error: 'User not found' }
  if (data.password) {
    data.password = crypto.createHash('sha256').update(data.password).digest('hex')
  }
  users[idx] = { ...users[idx], ...data }
  await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2))
  return { success: true }
}

// ─── GROUPS ───────────────────────────────────────────────────────────────────

async function getGroups() {
  try {
    const content = await fs.readFile(GROUPS_FILE, 'utf8')
    return JSON.parse(content)
  } catch(e) { return [] }
}

async function createGroup(data) {
  const groups = await getGroups()
  const group = {
    id: Date.now().toString(),
    name: data.name,
    description: data.description || '',
    sessionMinutes: parseInt(data.sessionMinutes) || 60,
    downloadKbps: parseInt(data.downloadKbps) || 0,
    uploadKbps: parseInt(data.uploadKbps) || 0,
    createdAt: new Date().toISOString()
  }
  groups.push(group)
  await ensureDir()
  await fs.writeFile(GROUPS_FILE, JSON.stringify(groups, null, 2))
  return { success: true, group }
}

async function deleteGroup(id) {
  const groups = await getGroups()
  const filtered = groups.filter(g => g.id !== id)
  await fs.writeFile(GROUPS_FILE, JSON.stringify(filtered, null, 2))
  return { success: true }
}

async function updateGroup(id, data) {
  const groups = await getGroups()
  const idx = groups.findIndex(g => g.id === id)
  if (idx === -1) return { success: false, error: 'Group not found' }
  groups[idx] = { ...groups[idx], ...data }
  await fs.writeFile(GROUPS_FILE, JSON.stringify(groups, null, 2))
  return { success: true }
}

// ─── SESSIONS ─────────────────────────────────────────────────────────────────

async function getSessions() {
  try {
    const content = await fs.readFile(SESSIONS_FILE, 'utf8')
    return JSON.parse(content)
  } catch(e) { return [] }
}

async function saveSessions(sessions) {
  await ensureDir()
  await fs.writeFile(SESSIONS_FILE, JSON.stringify(sessions, null, 2))
}

async function createSession(ip, portalId, username, durationMinutes) {
  const sessions = await getSessions()
  // Remove existing session for this IP
  const filtered = sessions.filter(s => s.ip !== ip)
  const session = {
    id: crypto.randomBytes(16).toString('hex'),
    ip,
    portalId,
    username: username || 'guest',
    expiresAt: new Date(Date.now() + durationMinutes * 60 * 1000).toISOString(),
    createdAt: new Date().toISOString()
  }
  filtered.push(session)
  await saveSessions(filtered)
  // Allow IP in PF
  await execAsync(`pfctl -t captive_allowed -T add ${ip} 2>/dev/null || true`)
  return session
}

async function expireSession(ip) {
  const sessions = await getSessions()
  const filtered = sessions.filter(s => s.ip !== ip)
  await saveSessions(filtered)
  await execAsync(`pfctl -t captive_allowed -T delete ${ip} 2>/dev/null || true`)
}

async function cleanExpiredSessions() {
  const sessions = await getSessions()
  const now = new Date()
  const valid = []
  for (const s of sessions) {
    if (new Date(s.expiresAt) > now) {
      valid.push(s)
    } else {
      try { await execAsync(`pfctl -t captive_allowed -T delete ${s.ip} 2>/dev/null || true`) } catch(e) {}
    }
  }
  await saveSessions(valid)
  return { expired: sessions.length - valid.length }
}

async function killSession(id) {
  const sessions = await getSessions()
  const session = sessions.find(s => s.id === id)
  if (!session) return { success: false, error: 'Session not found' }
  await expireSession(session.ip)
  return { success: true }
}

async function killAllSessions() {
  const sessions = await getSessions()
  for (const s of sessions) {
    try { await execAsync(`pfctl -t captive_allowed -T delete ${s.ip} 2>/dev/null || true`) } catch(e) {}
  }
  await saveSessions([])
  return { success: true, killed: sessions.length }
}

// ─── PORTAL AUTH (public endpoint, no JWT) ───────────────────────────────────

async function authenticatePortal(ip, portalId, username, password) {
  const portals = await getPortals()
  const portal = portals.find(p => p.id === portalId && p.enabled)
  if (!portal) return { success: false, error: 'Portal no encontrado' }

  let sessionMinutes = portal.sessionMinutes
  let dlKbps = portal.downloadKbps
  let ulKbps = portal.uploadKbps

  if (portal.mode === 'public') {
    // No auth needed, just create session
  } else if (portal.mode === 'users' || portal.mode === 'groups') {
    const users = await getUsers()
    const hash = crypto.createHash('sha256').update(password || '').digest('hex')
    const user = users.find(u => u.username === username && u.password === hash && u.enabled)
    if (!user) return { success: false, error: 'Usuario o contraseña incorrectos' }

    // If user has a group, use group limits
    if (user.groupId) {
      const groups = await getGroups()
      const group = groups.find(g => g.id === user.groupId)
      if (group) {
        sessionMinutes = group.sessionMinutes || sessionMinutes
        dlKbps = group.downloadKbps || dlKbps
        ulKbps = group.uploadKbps || ulKbps
      }
    }
  }

  // Create session
  const session = await createSession(ip, portalId, username, sessionMinutes)

  // Apply QoS if configured
  if (dlKbps > 0 || ulKbps > 0) {
    try {
      const { addRule } = require('./qos.service')
      await addRule({
        name: `Captive-${ip}`,
        target: 'ip',
        targetValue: ip,
        downloadKbps: dlKbps,
        uploadKbps: ulKbps
      })
    } catch(e) {}
  }

  return { success: true, session, expiresAt: session.expiresAt }
}

// ─── NGINX + PF ───────────────────────────────────────────────────────────────

async function generatePortalHTML(portal) {
  if (portal.template === 'custom' && portal.customHtml) {
    return portal.customHtml
  }
  if (portal.template === 'embed' && portal.embedCode) {
    return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${portal.title}</title></head><body style="margin:0;padding:0">${portal.embedCode}</body></html>`
  }

  // Default template
  const authFields = (portal.mode === 'users' || portal.mode === 'groups') ? `
    <div style="margin-bottom:16px">
      <input type="text" id="username" placeholder="Usuario" style="width:100%;padding:12px;border-radius:8px;border:1px solid #2d3148;background:#1a1f35;color:#e2e8f0;font-size:1rem;box-sizing:border-box;margin-bottom:8px">
      <input type="password" id="password" placeholder="Contraseña" style="width:100%;padding:12px;border-radius:8px;border:1px solid #2d3148;background:#1a1f35;color:#e2e8f0;font-size:1rem;box-sizing:border-box">
    </div>` : ''

  return `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${portal.title}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: ${portal.bgColor}; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
    .card { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; padding: 40px; max-width: 420px; width: 90%; text-align: center; backdrop-filter: blur(10px); }
    .logo { width: 80px; height: 80px; border-radius: 50%; background: ${portal.accentColor}; display: flex; align-items: center; justify-content: center; margin: 0 auto 24px; font-size: 2rem; }
    h1 { color: #e2e8f0; font-size: 1.6rem; margin-bottom: 8px; }
    p { color: #94a3b8; margin-bottom: 28px; font-size: 0.95rem; line-height: 1.5; }
    button { background: ${portal.accentColor}; color: white; border: none; padding: 14px 32px; border-radius: 10px; font-size: 1rem; font-weight: 600; cursor: pointer; width: 100%; transition: opacity 0.2s; }
    button:hover { opacity: 0.85; }
    button:disabled { opacity: 0.5; cursor: not-allowed; }
    .error { background: rgba(239,68,68,0.15); border: 1px solid rgba(239,68,68,0.3); color: #f87171; padding: 10px 14px; border-radius: 8px; margin-bottom: 16px; font-size: 0.85rem; display: none; }
    .success { background: rgba(34,197,94,0.15); border: 1px solid rgba(34,197,94,0.3); color: #22c55e; padding: 10px 14px; border-radius: 8px; margin-bottom: 16px; font-size: 0.85rem; display: none; }
    input { width: 100%; padding: 12px; border-radius: 8px; border: 1px solid #2d3148; background: #1a1f35; color: #e2e8f0; font-size: 1rem; margin-bottom: 8px; }
    input:focus { outline: none; border-color: ${portal.accentColor}; }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">${portal.logoUrl ? `<img src="${portal.logoUrl}" style="width:60px;height:60px;border-radius:50%;object-fit:cover">` : '🌐'}</div>
    <h1>${portal.title}</h1>
    <p>${portal.subtitle}</p>
    <div class="error" id="error-msg"></div>
    <div class="success" id="success-msg"></div>
    ${authFields}
    <button id="btn" onclick="connect()">${portal.buttonText}</button>
  </div>
  <script>
    const PORTAL_ID = '${portal.id}'
    async function connect() {
      const btn = document.getElementById('btn')
      const errorEl = document.getElementById('error-msg')
      const successEl = document.getElementById('success-msg')
      errorEl.style.display = 'none'
      btn.disabled = true
      btn.textContent = 'Conectando...'
      const body = { portalId: PORTAL_ID }
      const unField = document.getElementById('username')
      const pwField = document.getElementById('password')
      if (unField) body.username = unField.value
      if (pwField) body.password = pwField.value
      try {
        const res = await fetch('/captive/auth', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body)
        })
        const data = await res.json()
        if (data.success) {
          successEl.textContent = '✓ Conectado — redirigiendo...'
          successEl.style.display = 'block'
          setTimeout(() => window.location.href = 'http://detectportal.firefox.com/', 2000)
        } else {
          errorEl.textContent = data.error || 'Error de autenticación'
          errorEl.style.display = 'block'
          btn.disabled = false
          btn.textContent = '${portal.buttonText}'
        }
      } catch(e) {
        errorEl.textContent = 'Error de conexión'
        errorEl.style.display = 'block'
        btn.disabled = false
        btn.textContent = '${portal.buttonText}'
      }
    }
  </script>
</body>
</html>`
}

async function applyPortal(portal) {
  await ensureDir()

  // Generate portal HTML
  const html = await generatePortalHTML(portal)
  await fs.writeFile(`${PORTAL_HTML_DIR}/templates/${portal.id}.html`, html)

  // Generate nginx config
  await generateNginxConf()

  // Apply PF rules for this interface
  await applyPFCaptive()

  // Start/reload nginx
  try {
    const { stdout } = await execAsync('pgrep nginx 2>/dev/null || echo ""')
    if (stdout.trim()) {
      await execAsync('service nginx reload 2>/dev/null')
    } else {
      await execAsync('service nginx start 2>/dev/null')
    }
  } catch(e) {}
}

async function disablePortal(portal) {
  // Remove PF redirect for this interface
  await applyPFCaptive()
  await generateNginxConf()
  try { await execAsync('service nginx reload 2>/dev/null') } catch(e) {}
}

async function generateNginxConf() {
  const portals = await getPortals()
  const enabledPortals = portals.filter(p => p.enabled)

  // Use a high port to avoid conflicts with existing services
  const CAPTIVE_PORT = 4080

  let serverBlocks = enabledPortals.map(p => `
    # Portal: ${p.name} — ${p.interface}
    location /captive-portal-${p.id} {
      root ${PORTAL_HTML_DIR}/templates;
      try_files /${p.id}.html =404;
    }`).join('\n')

  const conf = `worker_processes 1;
events { worker_connections 1024; }
http {
  include mime.types;
  default_type application/octet-stream;
  server {
    listen ${CAPTIVE_PORT};
    server_name _;
    
    # Auth endpoint (proxied to backend)
    location /captive/auth {
      proxy_pass http://127.0.0.1:3000/api/captive/auth;
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header Content-Type application/json;
    }

    # Portal pages
    ${serverBlocks}

    # Default: serve portal based on source IP interface
    location / {
      proxy_pass http://127.0.0.1:3000/api/captive/portal?ip=$remote_addr;
      proxy_set_header X-Real-IP $remote_addr;
    }
  }
}
`
  await fs.writeFile(NGINX_CONF, conf)
}

async function applyPFCaptive() {
  const portals = await getPortals()
  const enabledPortals = portals.filter(p => p.enabled)

  const CAPTIVE_PORT = 4080

  let pfRules = `# Coltan OS Captive Portal (auto-generated)\n`
  pfRules += `table <captive_allowed> persist\n\n`

  // PF order: translation (rdr) MUST come before filtering (pass/block)
  let rdrRules = ``
  let filterRules = ``

  for (const portal of enabledPortals) {
    const iface = portal.interface
    // Translation rules first
    rdrRules += `# Portal: ${portal.name} on ${iface}\n`
    rdrRules += `rdr pass on ${iface} proto tcp from any to any port 80 -> 127.0.0.1 port ${CAPTIVE_PORT}\n`
    // Filtering rules after
    filterRules += `pass in quick on ${iface} from <captive_allowed> to any keep state\n`
    filterRules += `pass in quick on ${iface} proto udp from any to any port 53 keep state\n`
    filterRules += `pass in quick on ${iface} proto udp from any to any port 67 keep state\n`
    filterRules += `pass in quick on ${iface} proto tcp from any to 127.0.0.1 port ${CAPTIVE_PORT} keep state\n`
    filterRules += `block in quick on ${iface} from any to any\n\n`
  }
  pfRules += rdrRules + `\n` + filterRules

  await fs.writeFile('/etc/pf.captive.conf', pfRules)
  try { await execAsync('pfctl -a coltan/captive -f /etc/pf.captive.conf 2>/dev/null') } catch(e) {}

  // Ensure anchor is in main pf.conf
  try {
    const pfConf = await fs.readFile('/etc/pf.conf', 'utf8')
    if (!pfConf.includes('coltan/captive')) {
      const updated = pfConf.replace(
        'anchor "coltan/sites"',
        'anchor "coltan/captive"\nanchor "coltan/sites"'
      )
      await fs.writeFile('/etc/pf.conf', updated)
      await execAsync('pfctl -f /etc/pf.conf 2>/dev/null')
    }
  } catch(e) {}
}

// ─── RESTORE ON BOOT ─────────────────────────────────────────────────────────

async function restoreCaptive() {
  const portals = await getPortals()
  const enabled = portals.filter(p => p.enabled)
  if (enabled.length === 0) return { success: true, restored: 0 }
  await generateNginxConf()
  await applyPFCaptive()
  try { await execAsync('service nginx start 2>/dev/null') } catch(e) {}
  // Restore active sessions to PF table
  await cleanExpiredSessions()
  const sessions = await getSessions()
  for (const s of sessions) {
    try { await execAsync(`pfctl -t captive_allowed -T add ${s.ip} 2>/dev/null || true`) } catch(e) {}
  }
  return { success: true, restored: enabled.length }
}

module.exports = {
  getPortals, createPortal, updatePortal, deletePortal, enablePortal, disablePortalById,
  getUsers, createUser, deleteUser, updateUser,
  getGroups, createGroup, deleteGroup,
  getSessions, cleanExpiredSessions,
  authenticatePortal,
  updateGroup,
  killSession, killAllSessions,
  restoreCaptive
}
