'use strict'
const { exec } = require('child_process')
const { promisify } = require('util')
const execAsync = promisify(exec)
const fs = require('fs').promises
const https = require('https')
const http = require('http')

const UNBOUND_CONF = '/usr/local/etc/unbound/unbound.conf'
const BLOCKLIST_DIR = '/usr/local/etc/unbound/blocklists'
const BLOCKLIST_FILE = '/usr/local/etc/unbound/blocklists/blocklist.conf'
const SECURITY_FILE = '/usr/local/etc/coltan/security.json'
const UPDATE_LOG = '/usr/local/etc/coltan/dns-blocklist-update.log'

async function ensureDir() {
  await execAsync('mkdir -p /usr/local/etc/coltan')
  await execAsync(`mkdir -p ${BLOCKLIST_DIR}`)
}

// ─── CATALOGO DE LISTAS PROFESIONALES ─────────────────────────────────────────
// format: 'hosts' (lineas "0.0.0.0 dominio") o 'domains' (un dominio por linea, # = comentario)
const BUILTIN_LISTS = [
  { id: 'stevenblack',  name: 'StevenBlack Unified',   category: 'general',  format: 'hosts',
    url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
    desc: 'Lista combinada de ads, malware y tracking. Base solida y liviana.' },
  { id: 'adaway',       name: 'AdAway',                category: 'ads',      format: 'hosts',
    url: 'https://adaway.org/hosts.txt',
    desc: 'Lista clasica orientada a bloqueo de publicidad.' },
  { id: 'oisd_big',     name: 'OISD Big',               category: 'general',  format: 'domains',
    url: 'https://big.oisd.nl/domainswild2',
    desc: 'Muy baja tasa de falsos positivos. Actualiza cada ~24hs. Recomendada.' },
  { id: 'hagezi_multi', name: 'HaGeZi Multi (Normal)',  category: 'general',  format: 'domains',
    url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/multi-onlydomains.txt',
    desc: 'Ads, tracking, telemetria y metricas. Balance entre cobertura y compatibilidad.' },
  { id: 'hagezi_pro',   name: 'HaGeZi Pro',             category: 'general',  format: 'domains',
    url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt',
    desc: 'Cobertura mas agresiva: incluye scams, cryptojacking y mas trackers.' },
  { id: 'hagezi_tif',   name: 'HaGeZi Threat Intel Feed', category: 'malware', format: 'domains',
    url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif-onlydomains.txt',
    desc: 'Feed de amenazas activas: C2, malware, phishing recientes. Lista muy pesada (~2M dominios) - recomendada solo para equipos con 4GB de RAM o mas.',
    ramWarning: true },
  { id: '1hosts_lite',  name: '1Hosts Lite',            category: 'general',  format: 'domains',
    url: 'https://badmojr.github.io/1Hosts/Lite/domains.txt',
    desc: 'Alternativa curada a OISD, cobertura liviana.' },
  { id: 'phishing_army', name: 'Phishing Army',         category: 'malware',  format: 'domains',
    url: 'https://phishing.army/download/phishing_army_blocklist.txt',
    desc: 'Feed dedicado exclusivamente a dominios de phishing activos.' },
  { id: 'urlhaus',      name: 'URLhaus (abuse.ch)',     category: 'malware',  format: 'hosts',
    url: 'https://urlhaus.abuse.ch/downloads/hostfile/',
    desc: 'Feed profesional de malware y C2 mantenido por abuse.ch.' },
  { id: 'hagezi_nsfw',  name: 'HaGeZi NSFW',            category: 'adult',    format: 'domains',
    url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/nsfw-onlydomains.txt',
    desc: 'Contenido para adultos.' },
  { id: 'gambling',     name: 'Gambling (Blocklist Project)', category: 'gambling', format: 'hosts',
    url: 'https://raw.githubusercontent.com/blocklistproject/Lists/master/gambling.txt',
    desc: 'Sitios de apuestas y juego online.' },
]

function defaultSecurity() {
  return {
    dnsBlocker: {
      enabled: false,
      autoUpdate: true, // si esta en true, actualiza solo cada 24hs
      lists: BUILTIN_LISTS.map(l => ({
        id: l.id, enabled: l.id === 'oisd_big' || l.id === 'phishing_army', // combo liviano y de alta calidad por defecto
        lastCheck: null, lastCheckOk: null, domainCount: null
      })),
      customLists: [] // { id, name, url, category, format, enabled, lastCheck, lastCheckOk, domainCount }
    },
    lastUpdate: null,
    totalDomains: 0,
    whitelist: [],
    blacklist: []
  }
}

async function getSettings() {
  try {
    await ensureDir()
    const content = await fs.readFile(SECURITY_FILE, 'utf8')
    const saved = JSON.parse(content)
    // Merge defensivo: si agregamos listas nuevas al catalogo builtin, que aparezcan
    // en instalaciones existentes sin perder el estado de las que ya tenian configuradas.
    const existingIds = (saved.dnsBlocker?.lists || []).map(l => l.id)
    const missing = BUILTIN_LISTS.filter(l => !existingIds.includes(l.id))
      .map(l => ({ id: l.id, enabled: false, lastCheck: null, lastCheckOk: null, domainCount: null }))
    if (!saved.dnsBlocker) saved.dnsBlocker = defaultSecurity().dnsBlocker
    if (!saved.dnsBlocker.lists) saved.dnsBlocker.lists = []
    saved.dnsBlocker.lists = [...saved.dnsBlocker.lists, ...missing]
    if (saved.dnsBlocker.autoUpdate === undefined) saved.dnsBlocker.autoUpdate = true
    if (!saved.dnsBlocker.customLists) saved.dnsBlocker.customLists = []
    return saved
  } catch(e) {
    return defaultSecurity()
  }
}

async function saveSettings(settings) {
  await ensureDir()
  await fs.writeFile(SECURITY_FILE, JSON.stringify(settings, null, 2))
  return { success: true }
}

// Devuelve el catalogo completo (builtin con metadata + estado guardado, y custom) para el panel
async function getAvailableLists() {
  const settings = await getSettings()
  const savedBuiltin = settings.dnsBlocker.lists || []
  const builtin = BUILTIN_LISTS.map(l => {
    const state = savedBuiltin.find(s => s.id === l.id) || {}
    return { ...l, builtin: true, enabled: !!state.enabled, lastCheck: state.lastCheck || null,
             lastCheckOk: state.lastCheckOk ?? null, domainCount: state.domainCount ?? null }
  })
  const custom = (settings.dnsBlocker.customLists || []).map(c => ({ ...c, builtin: false }))
  return { lists: [...builtin, ...custom], autoUpdate: settings.dnsBlocker.autoUpdate, enabled: settings.dnsBlocker.enabled, lastUpdate: settings.lastUpdate, totalDomains: settings.totalDomains || 0 }
}

async function toggleList(id, enabled) {
  const settings = await getSettings()
  const builtinIdx = settings.dnsBlocker.lists.findIndex(l => l.id === id)
  if (builtinIdx >= 0) {
    settings.dnsBlocker.lists[builtinIdx].enabled = !!enabled
    await saveSettings(settings)
    return { success: true }
  }
  const customIdx = settings.dnsBlocker.customLists.findIndex(l => l.id === id)
  if (customIdx >= 0) {
    settings.dnsBlocker.customLists[customIdx].enabled = !!enabled
    await saveSettings(settings)
    return { success: true }
  }
  return { success: false, error: 'Lista no encontrada' }
}

async function addCustomList(name, url, category, format) {
  if (!name || !url) return { success: false, error: 'Nombre y URL requeridos' }
  const settings = await getSettings()
  const id = 'custom_' + Date.now().toString(36)
  settings.dnsBlocker.customLists.push({
    id, name, url, category: category || 'custom',
    format: format === 'domains' ? 'domains' : 'hosts',
    enabled: true, lastCheck: null, lastCheckOk: null, domainCount: null
  })
  await saveSettings(settings)
  return { success: true, id }
}

async function removeCustomList(id) {
  const settings = await getSettings()
  settings.dnsBlocker.customLists = settings.dnsBlocker.customLists.filter(l => l.id !== id)
  await saveSettings(settings)
  return { success: true }
}

// ─── DESCARGA CON TIMEOUT (sin dependencias externas) ─────────────────────────
function fetchUrl(url, timeoutMs = 20000) {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith('https') ? https : http
    // Forzar IPv4: algunos servidores (ej: OISD) tienen IPv6 sin ruta valida desde ciertas redes,
    // lo que hace que Node falle con AggregateError antes de probar IPv4 (a diferencia de curl).
    const req = lib.get(url, { headers: { 'User-Agent': 'ColtanOS-DNSBlocker/1.0' }, family: 4 }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        fetchUrl(res.headers.location, timeoutMs).then(resolve).catch(reject)
        return
      }
      if (res.statusCode !== 200) { reject(new Error('HTTP ' + res.statusCode)); return }
      let data = ''
      res.on('data', chunk => data += chunk)
      res.on('end', () => resolve(data))
    })
    req.on('error', reject)
    req.setTimeout(timeoutMs, () => { req.destroy(); reject(new Error('Timeout')) })
  })
}

// Extrae dominios de un texto segun el formato de la lista
function parseListContent(content, format) {
  const domains = new Set()
  const lines = content.split('\n')
  for (let line of lines) {
    line = line.trim()
    if (!line || line.startsWith('#') || line.startsWith('!')) continue
    let domain = null
    if (format === 'hosts') {
      const m = line.match(/^0\.0\.0\.0\s+(\S+)/) || line.match(/^127\.0\.0\.1\s+(\S+)/)
      if (m) domain = m[1]
    } else {
      // formato domains: puede venir "dominio.com" solo, o con wildcard "*.dominio.com" (OISD nuevo formato)
      let candidate = line
      if (candidate.startsWith('*.')) candidate = candidate.slice(2)
      const m = candidate.match(/^([a-zA-Z0-9][a-zA-Z0-9\-\.]*\.[a-zA-Z]{2,})$/)
      if (m) domain = m[1]
    }
    if (domain && domain !== 'localhost' && !domain.startsWith('0.0.0.0')) {
      domains.add(domain.toLowerCase())
    }
  }
  return domains
}

// ─── CHEQUEO DE DISPONIBILIDAD ─────────────────────────────────────────────────
async function checkListHealth(list) {
  try {
    const content = await fetchUrl(list.url, 35000)
    const domains = parseListContent(content, list.format)
    return { ok: domains.size > 0, domainCount: domains.size, error: domains.size === 0 ? 'La lista respondio pero no se pudo extraer ningun dominio (formato inesperado)' : null }
  } catch(e) {
    return { ok: false, domainCount: null, error: e.message }
  }
}

async function checkAllListsHealth() {
  const { lists } = await getAvailableLists()
  const results = []
  for (const list of lists) {
    const health = await checkListHealth(list)
    results.push({ id: list.id, name: list.name, ...health })
    // Persistir el resultado del chequeo
    const settings = await getSettings()
    const builtinIdx = settings.dnsBlocker.lists.findIndex(l => l.id === list.id)
    if (builtinIdx >= 0) {
      settings.dnsBlocker.lists[builtinIdx].lastCheck = new Date().toISOString()
      settings.dnsBlocker.lists[builtinIdx].lastCheckOk = health.ok
      settings.dnsBlocker.lists[builtinIdx].domainCount = health.domainCount
      await saveSettings(settings)
    } else {
      const customIdx = settings.dnsBlocker.customLists.findIndex(l => l.id === list.id)
      if (customIdx >= 0) {
        settings.dnsBlocker.customLists[customIdx].lastCheck = new Date().toISOString()
        settings.dnsBlocker.customLists[customIdx].lastCheckOk = health.ok
        settings.dnsBlocker.customLists[customIdx].domainCount = health.domainCount
        await saveSettings(settings)
      }
    }
  }
  return { results }
}

async function checkSingleListHealth(id) {
  const { lists } = await getAvailableLists()
  const list = lists.find(l => l.id === id)
  if (!list) return { success: false, error: 'Lista no encontrada' }
  const health = await checkListHealth(list)
  const settings = await getSettings()
  const builtinIdx = settings.dnsBlocker.lists.findIndex(l => l.id === id)
  if (builtinIdx >= 0) {
    settings.dnsBlocker.lists[builtinIdx].lastCheck = new Date().toISOString()
    settings.dnsBlocker.lists[builtinIdx].lastCheckOk = health.ok
    settings.dnsBlocker.lists[builtinIdx].domainCount = health.domainCount
  } else {
    const customIdx = settings.dnsBlocker.customLists.findIndex(l => l.id === id)
    if (customIdx >= 0) {
      settings.dnsBlocker.customLists[customIdx].lastCheck = new Date().toISOString()
      settings.dnsBlocker.customLists[customIdx].lastCheckOk = health.ok
      settings.dnsBlocker.customLists[customIdx].domainCount = health.domainCount
    }
  }
  await saveSettings(settings)
  return { success: true, ...health }
}

// ─── ACTUALIZACION REAL DE LAS LISTAS (genera blocklist.conf y recarga unbound) ─
let updateInProgress = false

async function appendLog(line) {
  try {
    await ensureDir()
    await fs.appendFile(UPDATE_LOG, `[${new Date().toISOString()}] ${line}\n`)
  } catch(e) {}
}

async function performBlocklistUpdate(trigger = 'manual') {
  if (updateInProgress) return { success: false, error: 'Ya hay una actualizacion en curso' }
  updateInProgress = true
  try {
    await ensureDir()
    await appendLog(`Iniciando actualizacion (${trigger})`)

    const { lists } = await getAvailableLists()
    const activeLists = lists.filter(l => l.enabled)

    if (activeLists.length === 0) {
      await appendLog('Sin listas activas, nada para actualizar')
      updateInProgress = false
      return { success: false, error: 'No hay ninguna lista activa. Activa al menos una lista antes de actualizar.' }
    }

    const allDomains = new Set()
    const settings = await getSettings()

    for (const list of activeLists) {
      try {
        await appendLog(`Descargando: ${list.name}`)
        const content = await fetchUrl(list.url, 30000)
        const domains = parseListContent(content, list.format)
        domains.forEach(d => allDomains.add(d))
        await appendLog(`${list.name}: ${domains.size} dominios`)

        // Actualizar estado de la lista
        const bIdx = settings.dnsBlocker.lists.findIndex(l => l.id === list.id)
        if (bIdx >= 0) { settings.dnsBlocker.lists[bIdx].lastCheck = new Date().toISOString(); settings.dnsBlocker.lists[bIdx].lastCheckOk = true; settings.dnsBlocker.lists[bIdx].domainCount = domains.size }
        const cIdx = settings.dnsBlocker.customLists.findIndex(l => l.id === list.id)
        if (cIdx >= 0) { settings.dnsBlocker.customLists[cIdx].lastCheck = new Date().toISOString(); settings.dnsBlocker.customLists[cIdx].lastCheckOk = true; settings.dnsBlocker.customLists[cIdx].domainCount = domains.size }
      } catch(e) {
        await appendLog(`ERROR en ${list.name}: ${e.message}`)
        const bIdx = settings.dnsBlocker.lists.findIndex(l => l.id === list.id)
        if (bIdx >= 0) { settings.dnsBlocker.lists[bIdx].lastCheck = new Date().toISOString(); settings.dnsBlocker.lists[bIdx].lastCheckOk = false }
        const cIdx = settings.dnsBlocker.customLists.findIndex(l => l.id === list.id)
        if (cIdx >= 0) { settings.dnsBlocker.customLists[cIdx].lastCheck = new Date().toISOString(); settings.dnsBlocker.customLists[cIdx].lastCheckOk = false }
      }
    }

    // Quitar whitelist del resultado final
    const whitelist = new Set((settings.whitelist || []).map(d => d.toLowerCase()))
    whitelist.forEach(d => allDomains.delete(d))

    // Generar blocklist.conf para Unbound
    let conf = `# Coltan OS DNS Blocklist - ${new Date().toISOString()}\n# Domains: ${allDomains.size}\n`
    for (const domain of allDomains) {
      conf += `    local-zone: "${domain}" redirect\n`
      conf += `    local-data: "${domain} A 0.0.0.0"\n`
    }
    // Agregar blacklist manual tambien
    for (const domain of (settings.blacklist || [])) {
      conf += `    local-zone: "${domain}" redirect\n`
      conf += `    local-data: "${domain} A 0.0.0.0"\n`
    }

    await fs.writeFile(BLOCKLIST_FILE, conf)
    await appendLog(`Total combinado: ${allDomains.size} dominios. Reiniciando Unbound...`)

    try { await execAsync('service unbound restart 2>&1') } catch(e) {
      await appendLog(`ADVERTENCIA: fallo al reiniciar unbound: ${e.message}`)
    }

    settings.lastUpdate = new Date().toISOString()
    settings.totalDomains = allDomains.size
    await saveSettings(settings)

    await appendLog('Actualizacion completada con exito')
    updateInProgress = false
    return { success: true, totalDomains: allDomains.size, listsProcessed: activeLists.length }
  } catch(e) {
    await appendLog(`ERROR FATAL: ${e.message}`)
    updateInProgress = false
    return { success: false, error: e.message }
  }
}

async function getUpdateLog() {
  try {
    const content = await fs.readFile(UPDATE_LOG, 'utf8')
    return content.trim().split('\n').slice(-100)
  } catch(e) { return [] }
}

async function setAutoUpdate(enabled) {
  const settings = await getSettings()
  settings.dnsBlocker.autoUpdate = !!enabled
  await saveSettings(settings)
  return { success: true }
}

// ─── AUTO-UPDATE CADA 24HS (in-process, sin depender de cron del sistema) ──────
let autoUpdateInterval = null

async function checkAndRunAutoUpdate() {
  try {
    const settings = await getSettings()
    if (!settings.dnsBlocker.enabled || !settings.dnsBlocker.autoUpdate) return
    const last = settings.lastUpdate ? new Date(settings.lastUpdate).getTime() : 0
    const hoursSince = (Date.now() - last) / (1000 * 60 * 60)
    if (hoursSince >= 24) {
      console.log('[DNSBlocker] Ejecutando actualizacion automatica (24hs)')
      await performBlocklistUpdate('auto-24h')
    }
  } catch(e) {}
}

function startAutoUpdateScheduler() {
  if (autoUpdateInterval) return
  // Chequea cada hora si ya pasaron 24hs desde el ultimo update
  autoUpdateInterval = setInterval(checkAndRunAutoUpdate, 60 * 60 * 1000)
  // Y una verificacion al arrancar (por si el sistema estuvo apagado)
  setTimeout(checkAndRunAutoUpdate, 30 * 1000)
}

// ─── STATUS GENERAL ─────────────────────────────────────────────────────────
async function getStatus() {
  const result = {
    unbound: { running: false, domains: 0 },
    clamav: { running: false, lastUpdate: null },
    suricata: { running: false }
  }
  try {
    const { stdout } = await execAsync('service unbound status 2>/dev/null')
    result.unbound.running = stdout.includes('is running')
  } catch(e) {}
  try {
    const { stdout } = await execAsync(`grep -c "local-zone" ${BLOCKLIST_FILE} 2>/dev/null || echo 0`)
    result.unbound.domains = parseInt(stdout.trim()) || 0
  } catch(e) {}
  try {
    const { stdout } = await execAsync('service clamav-clamd status 2>/dev/null || pgrep clamd')
    result.clamav.running = stdout.trim().length > 0
  } catch(e) {}
  try {
    const { stdout } = await execAsync('pgrep suricata 2>/dev/null')
    result.suricata.running = stdout.trim().length > 0
  } catch(e) {}
  return result
}

// ─── DNS BLOCKER ON/OFF ─────────────────────────────────────────────────────
async function enableDNSBlocker() {
  try {
    await execAsync('service unbound start 2>/dev/null || service unbound restart')
    const settings = await getSettings()
    settings.dnsBlocker.enabled = true
    await saveSettings(settings)
    startAutoUpdateScheduler()
    return { success: true }
  } catch(e) { return { success: false, error: e.message } }
}
async function disableDNSBlocker() {
  try {
    await execAsync('service unbound stop 2>/dev/null')
    const settings = await getSettings()
    settings.dnsBlocker.enabled = false
    await saveSettings(settings)
    return { success: true }
  } catch(e) { return { success: false, error: e.message } }
}

// Mantener compatibilidad con el endpoint viejo /api/security/dns/update
async function updateBlocklists() {
  return await performBlocklistUpdate('manual')
}

// ─── WHITELIST / BLACKLIST ──────────────────────────────────────────────────
async function addToWhitelist(domain) {
  const settings = await getSettings()
  if (!settings.whitelist.includes(domain)) settings.whitelist.push(domain)
  await saveSettings(settings)
  return { success: true }
}
async function removeFromWhitelist(domain) {
  const settings = await getSettings()
  settings.whitelist = settings.whitelist.filter(d => d !== domain)
  await saveSettings(settings)
  return { success: true }
}
async function addToBlacklist(domain) {
  const settings = await getSettings()
  if (!settings.blacklist.includes(domain)) settings.blacklist.push(domain)
  await saveSettings(settings)
  return { success: true }
}
async function removeFromBlacklist(domain) {
  const settings = await getSettings()
  settings.blacklist = settings.blacklist.filter(d => d !== domain)
  await saveSettings(settings)
  return { success: true }
}

async function testDomain(domain) {
  try {
    const { stdout } = await execAsync(`drill @127.0.0.1 ${domain} 2>&1 || dig @127.0.0.1 ${domain} 2>&1`)
    const blocked = stdout.includes('0.0.0.0')
    return { domain, blocked, raw: stdout.slice(0, 500) }
  } catch(e) { return { domain, blocked: null, error: e.message } }
}

async function getDNSStats() {
  const settings = await getSettings()
  return {
    totalDomains: settings.totalDomains || 0,
    lastUpdate: settings.lastUpdate,
    whitelistCount: (settings.whitelist || []).length,
    blacklistCount: (settings.blacklist || []).length,
  }
}

module.exports = {
  getDNSStats,
  getStatus, getSettings, saveSettings,
  enableDNSBlocker, disableDNSBlocker,
  updateBlocklists, getUpdateLog,
  addToWhitelist, removeFromWhitelist,
  addToBlacklist, removeFromBlacklist,
  testDomain,
  // Nuevo: gestion de listas
  getAvailableLists, toggleList, addCustomList, removeCustomList,
  checkListHealth: checkSingleListHealth, checkAllListsHealth,
  performBlocklistUpdate, setAutoUpdate, startAutoUpdateScheduler
}
