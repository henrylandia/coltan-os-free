'use strict'

const { exec } = require('child_process')
const { promisify } = require('util')
const execAsync = promisify(exec)
const fs = require('fs')

const MULTIWAN_FILE = '/usr/local/etc/coltan/multiwan.json'
const IFACES_FILE   = '/usr/local/etc/coltan/interfaces.json'

// Config por defecto
const DEFAULT_CONFIG = {
  enabled: false,
  mode: 'failover', // 'failover' | 'loadbalance'
  checkTarget: '8.8.8.8',
  checkInterval: 60,   // segundos
  failThreshold: 3,    // fallos consecutivos antes de failover
  recoverThreshold: 2, // pings ok consecutivos para recuperar
  wans: []
  // wans: [{ iface, gateway, weight, priority, enabled, status, failures, successes }]
}

let monitorInterval = null
let wanStates = {} // { iface: { failures, successes, status: 'up'|'down' } }
let alertCallback = null // función para emitir alertas al dashboard

function getConfig() {
  try {
    const c = JSON.parse(fs.readFileSync(MULTIWAN_FILE, 'utf8'))
    return { ...DEFAULT_CONFIG, ...c }
  } catch(e) { return { ...DEFAULT_CONFIG } }
}

function saveConfig(config) {
  fs.writeFileSync(MULTIWAN_FILE, JSON.stringify(config, null, 2))
}

function getIfaceRoles() {
  try { return JSON.parse(fs.readFileSync(IFACES_FILE, 'utf8')) } catch(e) { return {} }
}

// Obtener gateway de una interfaz desde el sistema
async function getIfaceGateway(iface) {
  try {
    const { stdout } = await execAsync(`netstat -rn | grep "^default" | awk '{print $2}' | head -1`)
    return stdout.trim()
  } catch(e) { return '' }
}

// Ping check para una WAN específica
async function pingCheck(iface, target) {
  try {
    await execAsync(`ping -c 1 -W 3 -S $(ifconfig ${iface} | grep "inet " | awk '{print $2}' | head -1) ${target} 2>/dev/null`)
    return true
  } catch(e) { return false }
}

// Obtener IP de una interfaz
async function getIfaceIP(iface) {
  try {
    const { stdout } = await execAsync(`ifconfig ${iface} | grep "inet " | awk '{print $2}' | head -1`)
    return stdout.trim()
  } catch(e) { return '' }
}

// Aplicar tabla de rutas para failover
async function applyFailoverRoutes(config) {
  const upWans = config.wans
    .filter(w => w.enabled && wanStates[w.iface]?.status === 'up')
    .sort((a, b) => a.priority - b.priority)

  if (upWans.length === 0) {
    console.log('[MultiWAN] Sin WANs activas disponibles')
    return
  }

  const primary = upWans[0]
  console.log(`[MultiWAN] Failover — usando ${primary.iface} (${primary.gateway}) como ruta principal`)

  try {
    // Eliminar ruta default actual
    await execAsync('route delete default 2>/dev/null || true')
    // Agregar nueva ruta default por la WAN primaria activa
    await execAsync(`route add default ${primary.gateway}`)
    console.log(`[MultiWAN] Ruta default → ${primary.gateway} via ${primary.iface}`)
  } catch(e) {
    console.error('[MultiWAN] Error aplicando ruta:', e.message)
  }
}

// Aplicar balanceo de carga con PF
async function applyLoadBalanceRoutes(config) {
  const upWans = config.wans
    .filter(w => w.enabled && wanStates[w.iface]?.status === 'up')

  if (upWans.length === 0) {
    console.log('[MultiWAN] Sin WANs activas para balanceo')
    return
  }

  if (upWans.length === 1) {
    // Solo una WAN activa — failover implícito
    await applyFailoverRoutes(config)
    return
  }

  console.log(`[MultiWAN] Load Balance — ${upWans.length} WANs activas`)

  // En FreeBSD usamos PF con múltiples tablas y round-robin
  // Generamos reglas NAT por cada WAN con peso
  try {
    const { generateAndReload } = require('./firewall.service')
    await generateAndReload()
    console.log('[MultiWAN] PF recargado con balanceo de carga')
  } catch(e) {
    console.error('[MultiWAN] Error recargando PF:', e.message)
  }
}

// Monitor loop principal
async function monitorLoop() {
  const config = getConfig()
  if (!config.enabled || config.wans.length === 0) return

  for (const wan of config.wans) {
    if (!wan.enabled) continue

    if (!wanStates[wan.iface]) {
      wanStates[wan.iface] = { failures: 0, successes: 0, status: 'unknown' }
    }

    const prevStatus = wanStates[wan.iface].status
    const ok = await pingCheck(wan.iface, config.checkTarget)

    if (ok) {
      wanStates[wan.iface].failures = 0
      wanStates[wan.iface].successes++
      if (prevStatus !== 'up' && wanStates[wan.iface].successes >= config.recoverThreshold) {
        wanStates[wan.iface].status = 'up'
        console.log(`[MultiWAN] ${wan.iface} RECUPERADA`)
        if (alertCallback) alertCallback({ type: 'wan_up', iface: wan.iface })
        await applyRoutes(config)
      }
    } else {
      wanStates[wan.iface].successes = 0
      wanStates[wan.iface].failures++
      if (prevStatus !== 'down' && wanStates[wan.iface].failures >= config.failThreshold) {
        wanStates[wan.iface].status = 'down'
        console.log(`[MultiWAN] ${wan.iface} CAIDA`)
        if (alertCallback) alertCallback({ type: 'wan_down', iface: wan.iface })
        await applyRoutes(config)
      }
    }

    // Actualizar estado en el archivo de config para que el panel lo lea
    wan.status = wanStates[wan.iface].status
    wan.failures = wanStates[wan.iface].failures
    wan.successes = wanStates[wan.iface].successes
    wan.lastCheck = new Date().toISOString()
  }

  // Guardar estado actualizado
  saveConfig(config)
}

async function applyRoutes(config) {
  if (config.mode === 'failover') {
    await applyFailoverRoutes(config)
  } else {
    await applyLoadBalanceRoutes(config)
  }
}

// API pública
async function getStatus() {
  const config = getConfig()
  const ifaces = getIfaceRoles()
  // Enriquecer con IPs actuales
  for (const wan of config.wans) {
    wan.ip = await getIfaceIP(wan.iface)
    wan.currentStatus = wanStates[wan.iface]?.status || 'unknown'
  }
  return { config, wanStates, availableIfaces: Object.keys(ifaces) }
}

async function addWan(iface, gateway, priority = 1, weight = 1) {
  const config = getConfig()
  if (config.wans.find(w => w.iface === iface)) {
    return { success: false, error: 'Esta interfaz ya está configurada como WAN' }
  }
  // Actualizar interfaces.json para marcarla como WAN
  const ifaces = getIfaceRoles()
  if (!ifaces[iface]) return { success: false, error: 'Interfaz no encontrada' }
  // Si no tiene gateway lo obtenemos del sistema
  const gw = gateway || await getIfaceGateway(iface)
  config.wans.push({
    iface, gateway: gw, priority, weight,
    enabled: true, status: 'unknown',
    failures: 0, successes: 0, lastCheck: null
  })
  saveConfig(config)
  wanStates[iface] = { failures: 0, successes: 0, status: 'unknown' }
  return { success: true }
}

async function removeWan(iface) {
  const config = getConfig()
  config.wans = config.wans.filter(w => w.iface !== iface)
  delete wanStates[iface]
  saveConfig(config)
  return { success: true }
}

async function updateConfig(updates) {
  const config = { ...getConfig(), ...updates }
  saveConfig(config)
  if (config.enabled) {
    await applyRoutes(config)
  }
  return { success: true, config }
}

function setAlertCallback(cb) { alertCallback = cb }

function startMonitor() {
  if (monitorInterval) return
  const config = getConfig()
  if (!config.enabled) {
    console.log('[MultiWAN] Módulo deshabilitado')
    return
  }
  console.log(`[MultiWAN] Monitor iniciado — modo: ${config.mode}, intervalo: ${config.checkInterval}s`)
  // Inicializar estados
  config.wans.forEach(w => {
    wanStates[w.iface] = { failures: 0, successes: 0, status: 'unknown' }
  })
  // Primera verificación inmediata
  monitorLoop()
  monitorInterval = setInterval(monitorLoop, config.checkInterval * 1000)
}

function stopMonitor() {
  if (monitorInterval) { clearInterval(monitorInterval); monitorInterval = null }
  console.log('[MultiWAN] Monitor detenido')
}

module.exports = {
  getStatus, addWan, removeWan, updateConfig,
  startMonitor, stopMonitor, setAlertCallback, getConfig
}
