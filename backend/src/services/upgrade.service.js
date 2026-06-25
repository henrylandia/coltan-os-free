'use strict'
const { exec } = require('child_process')
const { promisify } = require('util')
const execAsync = promisify(exec)
const fs = require('fs')
const path = require('path')

const UPGRADE_KEY = '/usr/local/etc/coltan/upgrade-key'
const PREMIUM_REPO_SSH = 'git@github.com-coltanos-upgrade:henrylandia/coltan-os.git'
const TMP_CLONE = '/tmp/coltan-premium-upgrade'
const COLTANOS_ROOT = '/opt/coltanos'

// Archivos/carpetas premium que se copian desde el repo premium al free
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
  'backend/src/server.js',           // server.js completo del premium (ya tiene todo registrado + middleware)
  'backend/src/middleware/license.js', // se mantiene siempre, viene del premium
  'backend/src/routes/suricata.routes.js', // version completa (con autoblock habilitado)
  'frontend/public/pages/qos.html',
  'frontend/public/pages/sites.html',
  'frontend/public/pages/security.html', // version completa premium (reemplaza la free bloqueada)
  'frontend/public/pages/reports.html',
  'frontend/public/js/sidebar.js',  // sidebar completo premium (sin estrellas, todo desbloqueado)
  'frontend/public/index.html'      // dashboard completo premium
]

async function isUpgradeAvailable() {
  return fs.existsSync(UPGRADE_KEY)
}

async function performUpgrade() {
  const log = []
  try {
    log.push('[Upgrade] Iniciando actualizacion a Premium...')

    // 1. Configurar SSH con la upgrade key
    const sshConfigDir = '/root/.ssh'
    if (!fs.existsSync(sshConfigDir)) fs.mkdirSync(sshConfigDir, { recursive: true })

    const sshConfig = `\nHost github.com-coltanos-upgrade\n    HostName github.com\n    User git\n    IdentityFile ${UPGRADE_KEY}\n    IdentitiesOnly yes\n`
    const configPath = path.join(sshConfigDir, 'config')
    let existing = fs.existsSync(configPath) ? fs.readFileSync(configPath, 'utf8') : ''
    if (!existing.includes('github.com-coltanos-upgrade')) {
      fs.appendFileSync(configPath, sshConfig)
    }
    await execAsync(`chmod 600 ${UPGRADE_KEY}`)

    // 2. Clonar el repo premium en un tmp
    log.push('[Upgrade] Descargando codigo premium...')
    await execAsync(`rm -rf ${TMP_CLONE}`)
    await execAsync(`git clone --depth 1 ${PREMIUM_REPO_SSH} ${TMP_CLONE}`)

    // 3. Backup de seguridad del codigo actual antes de tocar nada
    const backupDir = `/opt/coltanos-backup-${Date.now()}`
    log.push('[Upgrade] Backup de seguridad en ' + backupDir)
    await execAsync(`cp -r ${COLTANOS_ROOT} ${backupDir}`)

    // 4. Copiar SOLO los archivos premium definidos (no tocar config del cliente)
    for (const file of PREMIUM_FILES) {
      const src = path.join(TMP_CLONE, file)
      const dest = path.join(COLTANOS_ROOT, file)
      if (fs.existsSync(src)) {
        fs.mkdirSync(path.dirname(dest), { recursive: true })
        fs.copyFileSync(src, dest)
        log.push('[Upgrade] Actualizado: ' + file)
      } else {
        log.push('[Upgrade] AVISO: no encontrado en repo premium: ' + file)
      }
    }

    // 5. Instalar dependencias nuevas si el package.json cambio
    log.push('[Upgrade] Instalando dependencias...')
    await execAsync(`cd ${COLTANOS_ROOT}/backend && npm install --production 2>&1`)

    // 6. Limpiar
    await execAsync(`rm -rf ${TMP_CLONE}`)

    // Cambiar remote al repo premium para Coltan OS Updates
    try { await execAsync('git -C ' + COLTANOS_ROOT + ' remote set-url origin git@github.com-coltanos-upgrade:henrylandia/coltan-os.git'); log.push('[Upgrade] Remote → premium') } catch(e) {}
    log.push('[Upgrade] Completado. Reiniciando backend...')
    fs.writeFileSync('/usr/local/etc/coltan/upgrade-log.txt', log.join('\n'))

    // 7. Reiniciar PM2 (esto mata el proceso actual, debe ser lo ultimo)
    setTimeout(() => {
      exec('pm2 restart coltanos-backend')
    }, 1000)

    return { success: true, log, backupDir }
  } catch(e) {
    log.push('[Upgrade] ERROR: ' + e.message)
    fs.writeFileSync('/usr/local/etc/coltan/upgrade-log.txt', log.join('\n'))
    return { success: false, error: e.message, log }
  }
}

module.exports = { isUpgradeAvailable, performUpgrade }
