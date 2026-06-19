'use strict'
const { exec } = require('child_process')
const { promisify } = require('util')
const execAsync = promisify(exec)
const fs = require('fs')
const path = require('path')

const FREE_REPO_SSH = 'git@github.com-coltanos-upgrade:henrylandia/coltan-os-free.git'
const TMP_CLONE = '/tmp/coltan-free-downgrade'
const COLTANOS_ROOT = '/opt/coltanos'
const DOWNGRADE_FLAG = '/usr/local/etc/coltan/.downgrade-done'

// Archivos premium que se reemplazan por su version free al hacer downgrade
const PREMIUM_FILES = [
  'backend/src/routes/qos.routes.js',
  'backend/src/services/qos.service.js',
  'backend/src/routes/sites.routes.js',
  'backend/src/services/sites.service.js',
  'backend/src/routes/security.routes.js',
  'backend/src/services/security.service.js',
  'backend/src/routes/reports.routes.js',
  'backend/src/services/db.service.js',
  'backend/src/services/collectors.service.js',
  'backend/src/services/suricata-autoblock.js',
  'backend/src/server.js',
  'backend/src/routes/suricata.routes.js',
  'frontend/public/pages/qos.html',
  'frontend/public/pages/sites.html',
  'frontend/public/pages/security.html',
  'frontend/public/pages/reports.html',
  'frontend/public/js/sidebar.js',
  'frontend/public/index.html'
]

// Archivos que solo deben ELIMINARSE si existen (existian en premium pero no en free)
const PREMIUM_ONLY_FILES_TO_DELETE = [
  'backend/src/routes/qos.routes.js',
  'backend/src/services/qos.service.js',
  'backend/src/routes/sites.routes.js',
  'backend/src/services/sites.service.js',
  'backend/src/routes/security.routes.js',
  'backend/src/services/security.service.js',
  'backend/src/routes/reports.routes.js',
  'backend/src/services/db.service.js',
  'backend/src/services/collectors.service.js',
  'backend/src/services/suricata-autoblock.js'
]

async function needsDowngrade() {
  // Si existe sites.service.js (modulo premium) pero la licencia no esta activa, hay que downgradear
  const hasPremiumModule = fs.existsSync(path.join(COLTANOS_ROOT, 'backend/src/services/sites.service.js'))
  return hasPremiumModule
}

async function performDowngrade() {
  const log = []
  try {
    log.push('[Downgrade] Licencia inactiva detectada - revirtiendo a Free...')

    await execAsync(`rm -rf ${TMP_CLONE}`)
    log.push('[Downgrade] Descargando codigo Free...')
    await execAsync(`git clone --depth 1 https://github.com/henrylandia/coltan-os-free.git ${TMP_CLONE}`)

    const backupDir = `/opt/coltanos-backup-downgrade-${Date.now()}`
    log.push('[Downgrade] Backup de seguridad en ' + backupDir)
    await execAsync(`cp -r ${COLTANOS_ROOT} ${backupDir}`)

    // 1. Borrar archivos exclusivos de premium que no deben existir en free
    for (const file of PREMIUM_ONLY_FILES_TO_DELETE) {
      const target = path.join(COLTANOS_ROOT, file)
      if (fs.existsSync(target)) {
        fs.unlinkSync(target)
        log.push('[Downgrade] Eliminado: ' + file)
      }
    }

    // 2. Copiar las versiones free de los archivos compartidos (server.js, sidebar, etc)
    for (const file of PREMIUM_FILES) {
      const src = path.join(TMP_CLONE, file)
      const dest = path.join(COLTANOS_ROOT, file)
      if (fs.existsSync(src)) {
        fs.mkdirSync(path.dirname(dest), { recursive: true })
        fs.copyFileSync(src, dest)
        log.push('[Downgrade] Restaurado a Free: ' + file)
      }
    }

    // 3. Copiar paginas estaticas free que tal vez no existian (suricata.html ya no se usa, security.html se reemplaza)
    const extraFreeFiles = ['backend/src/services/upgrade.service.js']
    for (const file of extraFreeFiles) {
      const src = path.join(TMP_CLONE, file)
      const dest = path.join(COLTANOS_ROOT, file)
      if (fs.existsSync(src) && !fs.existsSync(dest)) {
        fs.mkdirSync(path.dirname(dest), { recursive: true })
        fs.copyFileSync(src, dest)
      }
    }

    await execAsync(`cd ${COLTANOS_ROOT}/backend && npm install --production 2>&1`)
    await execAsync(`rm -rf ${TMP_CLONE}`)

    log.push('[Downgrade] Completado. Reiniciando backend...')
    fs.writeFileSync('/usr/local/etc/coltan/downgrade-log.txt', log.join('\n'))

    setTimeout(() => {
      exec('pm2 restart coltanos-backend')
    }, 1000)

    return { success: true, log }
  } catch(e) {
    log.push('[Downgrade] ERROR: ' + e.message)
    fs.writeFileSync('/usr/local/etc/coltan/downgrade-log.txt', log.join('\n'))
    return { success: false, error: e.message, log }
  }
}

module.exports = { needsDowngrade, performDowngrade }
