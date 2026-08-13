'use strict'

const { exec } = require('child_process')
const { promisify } = require('util')
const execAsync = promisify(exec)
const fs = require('fs').promises
const fsSync = require('fs')
const path = require('path')
const nodemailer = require('nodemailer')
const crypto = require('crypto')

// ─── ENCRIPTACION AES-256-GCM ──────────────────────────────────────────────
function encryptData(plainText, password) {
  const salt = crypto.randomBytes(16)
  const key = crypto.scryptSync(password, salt, 32)
  const iv = crypto.randomBytes(12)
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)
  const encrypted = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()])
  const authTag = cipher.getAuthTag()
  // Empaquetamos todo en un solo objeto: salt + iv + authTag + datos encriptados
  return JSON.stringify({
    encrypted: true,
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
    data: encrypted.toString('base64')
  })
}

function decryptData(encryptedJson, password) {
  const payload = typeof encryptedJson === 'string' ? JSON.parse(encryptedJson) : encryptedJson
  if (!payload.encrypted) throw new Error('El archivo no esta encriptado')
  const salt = Buffer.from(payload.salt, 'base64')
  const iv = Buffer.from(payload.iv, 'base64')
  const authTag = Buffer.from(payload.authTag, 'base64')
  const data = Buffer.from(payload.data, 'base64')
  const key = crypto.scryptSync(password, salt, 32)
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv)
  decipher.setAuthTag(authTag)
  try {
    const decrypted = Buffer.concat([decipher.update(data), decipher.final()])
    return decrypted.toString('utf8')
  } catch(e) {
    throw new Error('Clave incorrecta o archivo corrupto')
  }
}

const BACKUPS_DIR = '/var/db/coltanos/config-backups'
const POLICY_FILE = '/usr/local/etc/coltan/config-backup-policy.json'
const CRONTAB = '/etc/crontab'

// Archivos de configuracion que se incluyen en el backup (todo JSON, liviano)
const CONFIG_FILES = [
  { key: 'interfaces',    path: '/usr/local/etc/coltan/interfaces.json' },
  { key: 'firewallRules', path: '/usr/local/etc/coltan/firewall-rules.json' },
  { key: 'blockedIps',    path: '/usr/local/etc/coltan/blocked-ips.json' },
  { key: 'portForwards',  path: '/usr/local/etc/coltan/port-forwards.json' },
  { key: 'multiwan',      path: '/usr/local/etc/coltan/multiwan.json' },
  { key: 'wgConfig',      path: '/usr/local/etc/coltan/wg-config.json' },
  { key: 'wgPeers',       path: '/usr/local/etc/coltan/wg-peers.json' },
  { key: 'security',      path: '/usr/local/etc/coltan/security.json' },
  { key: 'blockedSites',  path: '/usr/local/etc/coltan/blocked-sites.json' },
  { key: 'blockedGroups', path: '/usr/local/etc/coltan/blocked-groups.json' },
  { key: 'customCategories', path: '/usr/local/etc/coltan/custom-categories.json' },
  { key: 'qos',           path: '/usr/local/etc/coltan/qos.json' },
  { key: 'vlans',         path: '/usr/local/etc/coltan/vlans.json' },
  { key: 'wanDns',        path: '/usr/local/etc/coltan/wan-dns.json' },
  { key: 'suricata',      path: '/usr/local/etc/coltan/suricata.json' },
  { key: 'settings',      path: '/usr/local/etc/coltan/settings.json' },
  { key: 'autoblockWhitelist', path: '/usr/local/etc/coltan/autoblock-whitelist.json' },
]

async function ensureDirs() {
  await execAsync(`mkdir -p ${BACKUPS_DIR}`)
  await execAsync('mkdir -p /usr/local/etc/coltan')
}

function readJsonSafe(filePath) {
  try {
    return JSON.parse(fsSync.readFileSync(filePath, 'utf8'))
  } catch(e) { return null }
}

// ─── EXPORT ────────────────────────────────────────────────────────────────

async function buildConfigSnapshot() {
  const data = {}
  for (const f of CONFIG_FILES) {
    const content = readJsonSafe(f.path)
    if (content !== null) data[f.key] = content
  }

  // Metadata: interfaces fisicas actuales (para el mapeo al restaurar)
  let physicalInterfaces = []
  try {
    const { stdout } = await execAsync('ifconfig -l')
    physicalInterfaces = stdout.trim().split(/\s+/).filter(n => n !== 'lo0')
  } catch(e) {}

  let hostname = 'coltanos'
  try {
    const { stdout } = await execAsync('hostname')
    hostname = stdout.trim()
  } catch(e) {}

  return {
    version: 1,
    createdAt: new Date().toISOString(),
    hostname,
    physicalInterfacesAtBackupTime: physicalInterfaces,
    config: data
  }
}

async function createBackup(trigger = 'manual', encryptPassword = null) {
  await ensureDirs()
  const snapshot = await buildConfigSnapshot()
  const isEncrypted = !!encryptPassword
  const filename = `coltanos-config-${snapshot.hostname}-${Date.now()}${isEncrypted ? '.enc' : ''}.json`
  const filePath = path.join(BACKUPS_DIR, filename)

  const plainJson = JSON.stringify(snapshot, null, 2)
  const finalContent = isEncrypted ? encryptData(plainJson, encryptPassword) : plainJson
  await fs.writeFile(filePath, finalContent)

  await applyRetention()

  // Enviar por mail si esta configurado
  try {
    const policy = await getPolicy()
    if (policy.emailEnabled) {
      await sendBackupByEmail(filePath, filename)
    }
  } catch(e) {
    console.error('[ConfigBackup] Error enviando email:', e.message)
  }

  return { success: true, filename, path: filePath, createdAt: snapshot.createdAt, encrypted: isEncrypted }
}

async function applyRetention() {
  const policy = await getPolicy()
  const maxKeep = parseInt(policy.retention) || 10
  const files = await listBackups()
  if (files.length > maxKeep) {
    const toDelete = files.slice(maxKeep) // listBackups ya viene ordenado mas reciente primero
    for (const f of toDelete) {
      try { await fs.unlink(path.join(BACKUPS_DIR, f.filename)) } catch(e) {}
    }
  }
}

async function sendBackupByEmail(filePath, filename) {
  const settingsRaw = readJsonSafe('/usr/local/etc/coltan/settings.json')
  const notif = settingsRaw?.notifications
  if (!notif || !notif.emailEnabled || !notif.smtpHost) return

  const transporter = nodemailer.createTransport({
    host: notif.smtpHost,
    port: parseInt(notif.smtpPort) || 587,
    secure: parseInt(notif.smtpPort) === 465,
    auth: { user: notif.smtpUser, pass: notif.smtpPass },
    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 10000
  })

  const content = await fs.readFile(filePath, 'utf8')

  await transporter.sendMail({
    from: notif.smtpUser,
    to: notif.emailTo,
    subject: `Coltan OS — Backup de configuración (${filename})`,
    text: `Se adjunta el backup automático de configuración de Coltan OS.\n\nFecha: ${new Date().toLocaleString()}`,
    attachments: [{ filename, content }]
  })
}

// ─── LIST / DOWNLOAD / DELETE ─────────────────────────────────────────────

async function listBackups() {
  await ensureDirs()
  try {
    const files = await fs.readdir(BACKUPS_DIR)
    const backups = []
    for (const f of files.filter(f => f.endsWith('.json'))) {
      try {
        const stat = await fs.stat(path.join(BACKUPS_DIR, f))
        backups.push({
          filename: f,
          size: stat.size,
          createdAt: stat.mtime.toISOString()
        })
      } catch(e) {}
    }
    return backups.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
  } catch(e) { return [] }
}

async function getBackupContent(filename) {
  // Prevenir path traversal
  const safe = path.basename(filename)
  const filePath = path.join(BACKUPS_DIR, safe)
  return await fs.readFile(filePath, 'utf8')
}

async function deleteBackup(filename) {
  const safe = path.basename(filename)
  const filePath = path.join(BACKUPS_DIR, safe)
  await fs.unlink(filePath)
  return { success: true }
}

// ─── RESTORE — con mapeo de interfaces ────────────────────────────────────

async function getRestorePreview(snapshotJson, decryptPassword = null) {
  let snapshot
  try {
    let raw = snapshotJson
    // Detectar si esta encriptado (viene como string JSON con encrypted:true)
    const parsed = typeof snapshotJson === 'string' ? JSON.parse(snapshotJson) : snapshotJson
    if (parsed.encrypted) {
      if (!decryptPassword) return { error: 'ENCRYPTED', encrypted: true }
      raw = decryptData(parsed, decryptPassword)
    } else {
      raw = typeof snapshotJson === 'string' ? snapshotJson : JSON.stringify(snapshotJson)
    }
    snapshot = JSON.parse(raw)
  } catch(e) {
    return { error: e.message === 'Clave incorrecta o archivo corrupto' ? e.message : 'Archivo de backup invalido o corrupto' }
  }

  if (!snapshot.config) return { error: 'Formato de backup no reconocido' }

  // Interfaces guardadas en el backup (con su rol asignado en ese momento)
  const oldInterfaces = snapshot.config.interfaces || {}
  const oldIfaceList = Object.entries(oldInterfaces).map(([name, v]) => ({
    name, role: v.role, description: v.description || '', vlan: !!v.vlan
  }))

  // Interfaces fisicas reales del equipo actual
  let currentInterfaces = []
  try {
    const { stdout } = await execAsync('ifconfig -l')
    currentInterfaces = stdout.trim().split(/\s+/).filter(n => n !== 'lo0')
  } catch(e) {}

  const needsMapping = oldIfaceList.some(o => !o.vlan) &&
    !oldIfaceList.filter(o => !o.vlan).every(o => currentInterfaces.includes(o.name))

  return {
    createdAt: snapshot.createdAt,
    hostname: snapshot.hostname,
    oldInterfaces: oldIfaceList,
    currentInterfaces,
    needsMapping,
    modulesIncluded: Object.keys(snapshot.config)
  }
}

async function restoreBackup(snapshotJson, interfaceMapping, decryptPassword = null) {
  let snapshot
  try {
    let raw
    const parsed = typeof snapshotJson === 'string' ? JSON.parse(snapshotJson) : snapshotJson
    if (parsed.encrypted) {
      if (!decryptPassword) return { success: false, error: 'Este backup esta encriptado, se requiere la clave' }
      raw = decryptData(parsed, decryptPassword)
    } else {
      raw = typeof snapshotJson === 'string' ? snapshotJson : JSON.stringify(snapshotJson)
    }
    snapshot = JSON.parse(raw)
  } catch(e) {
    return { success: false, error: e.message === 'Clave incorrecta o archivo corrupto' ? e.message : 'Archivo de backup invalido' }
  }
  if (!snapshot.config) return { success: false, error: 'Formato de backup no reconocido' }

  const config = { ...snapshot.config }

  // Aplicar el mapeo de interfaces (old_name -> new_name) a TODOS los archivos que referencien interfaces
  if (interfaceMapping && Object.keys(interfaceMapping).length > 0) {
    const remapName = (name) => interfaceMapping[name] || name

    // interfaces.json: reconstruir con los nuevos nombres
    if (config.interfaces) {
      const remapped = {}
      for (const [oldName, val] of Object.entries(config.interfaces)) {
        if (val.vlan) {
          // Las VLAN dependen de su interfaz padre, remapeamos el parent tambien
          remapped[oldName] = { ...val, parent: remapName(val.parent) }
        } else {
          const newName = remapName(oldName)
          remapped[newName] = val
        }
      }
      config.interfaces = remapped
    }

    // firewall-rules.json: remapear el campo interface de cada regla
    if (Array.isArray(config.firewallRules)) {
      config.firewallRules = config.firewallRules.map(r => ({
        ...r, interface: r.interface && r.interface !== 'any' ? remapName(r.interface) : r.interface
      }))
    }

    // multiwan.json: remapear iface de cada wan
    if (config.multiwan?.wans) {
      config.multiwan = {
        ...config.multiwan,
        wans: config.multiwan.wans.map(w => ({ ...w, iface: remapName(w.iface) }))
      }
    }

    // suricata.json: remapear array de interfaces monitoreadas
    if (config.suricata?.interfaces) {
      config.suricata = {
        ...config.suricata,
        interfaces: config.suricata.interfaces.map(remapName)
      }
    }
  }

  // Escribir cada archivo de config restaurado
  const writtenFiles = []
  for (const f of CONFIG_FILES) {
    if (config[f.key] !== undefined) {
      try {
        await fs.writeFile(f.path, JSON.stringify(config[f.key], null, 2))
        writtenFiles.push(f.key)
      } catch(e) {
        console.error(`[ConfigBackup] Error escribiendo ${f.path}:`, e.message)
      }
    }
  }

  // Regenerar firewall con la config restaurada
  try {
    const { generateAndReload } = require('./firewall.service')
    await generateAndReload()
  } catch(e) {}

  return { success: true, restoredModules: writtenFiles, message: 'Configuracion restaurada. Algunos servicios pueden necesitar reinicio manual (WireGuard, OpenVPN, Suricata, DHCP).' }
}

// ─── POLICY (programacion automatica) ─────────────────────────────────────

async function getPolicy() {
  try {
    await ensureDirs()
    const content = await fs.readFile(POLICY_FILE, 'utf8')
    return JSON.parse(content)
  } catch(e) {
    return {
      enabled: false,
      frequency: 'daily', // hourly | daily | weekly | monthly
      hour: 2,
      retention: 10,
      emailEnabled: false
    }
  }
}

async function savePolicy(policy) {
  await ensureDirs()
  const current = await getPolicy()
  const merged = { ...current, ...policy }
  await fs.writeFile(POLICY_FILE, JSON.stringify(merged, null, 2))
  await updateCron(merged)
  return { success: true, policy: merged }
}

function frequencyToCron(frequency, hour) {
  const h = parseInt(hour) || 2
  switch(frequency) {
    case 'hourly':  return '0 * * * *'
    case 'daily':   return `0 ${h} * * *`
    case 'weekly':  return `0 ${h} * * 0`
    case 'monthly': return `0 ${h} 1 * *`
    default:        return `0 ${h} * * *`
  }
}

async function updateCron(policy) {
  try {
    let crontab = await fs.readFile(CRONTAB, 'utf8')
    crontab = crontab.split('\n').filter(line => !line.includes('# coltan-config-backup')).join('\n')

    if (policy.enabled) {
      const cron = frequencyToCron(policy.frequency, policy.hour)
      const cmd = `${cron}\troot\t/usr/local/bin/node -e "require('/opt/coltanos/backend/src/services/config-backup.service').createBackup('scheduled')" >> /var/log/coltan-config-backup.log 2>&1 # coltan-config-backup`
      crontab += `\n${cmd}`
    }

    await fs.writeFile(CRONTAB, crontab.trim() + '\n')
  } catch(e) {
    console.error('[ConfigBackup] Error actualizando crontab:', e.message)
  }
}

module.exports = {
  createBackup, listBackups, getBackupContent, deleteBackup,
  getRestorePreview, restoreBackup,
  getPolicy, savePolicy
}
