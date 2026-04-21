'use strict'

const { exec } = require('child_process')
const { promisify } = require('util')
const execAsync = promisify(exec)
const fs = require('fs').promises

const SMB_CONF = '/usr/local/etc/smb4.conf'

async function ensurePFRules() {
  try {
    const { stdout } = await execAsync('pfctl -sr 2>/dev/null')
    if (!stdout.includes('445')) {
      await execAsync('echo "pass in on em0 proto tcp to port { 139, 445 } keep state" >> /etc/pf.conf')
      await execAsync('pfctl -f /etc/pf.conf')
    }
  } catch(e) {}
}

async function getShares() {
  try {
    const content = await fs.readFile(SMB_CONF, 'utf8')
    const shares = []
    const sections = content.split(/^\[/m).slice(1)
    for (const section of sections) {
      const lines = section.split('\n')
      const name = lines[0].replace(']', '').trim()
      if (name === 'global' || name === 'homes') continue
      const share = { name }
      for (const line of lines.slice(1)) {
        const m = line.match(/^\s*([^=]+?)\s*=\s*(.+)/)
        if (m) share[m[1].trim()] = m[2].trim()
      }
      shares.push(share)
    }
    return shares
  } catch(e) { return [] }
}

async function addShare(name, path, comment = '', writable = true, browseable = true, validUsers = '') {
  try {
    // Create directory
    await execAsync(`mkdir -p ${path}`)

    // Set ownership and permissions automatically
    if (validUsers) {
      const firstUser = validUsers.trim().split(/\s+/)[0].replace('@','')
      try {
        await execAsync(`chown ${firstUser}:wheel ${path}`)
      } catch(e) {
        await execAsync(`chown root:wheel ${path}`)
      }
    } else {
      await execAsync(`chown root:wheel ${path}`)
    }
    await execAsync(`chmod 770 ${path}`)

    // Ensure PF allows Samba ports
    await ensurePFRules()

    const content = await fs.readFile(SMB_CONF, 'utf8')
    const shareConfig = `
[${name}]
   comment = ${comment || name}
   path = ${path}
   writable = ${writable ? 'yes' : 'no'}
   browseable = ${browseable ? 'yes' : 'no'}
   ${validUsers ? `valid users = ${validUsers}` : ''}
   create mask = 0660
   directory mask = 0770
`
    await fs.writeFile(SMB_CONF, content + shareConfig)
    await execAsync('service samba_server reload')
    return { success: true }
  } catch(e) {
    return { success: false, error: e.message }
  }
}

async function deleteShare(name) {
  try {
    const content = await fs.readFile(SMB_CONF, 'utf8')
    const regex = new RegExp(`\\[${name}\\][\\s\\S]*?(?=\\n\\[|$)`, 'g')
    const newContent = content.replace(regex, '').trim()
    await fs.writeFile(SMB_CONF, newContent + '\n')
    await execAsync('service samba_server reload')
    return { success: true }
  } catch(e) {
    return { success: false, error: e.message }
  }
}

async function getUsers() {
  try {
    const { stdout } = await execAsync('pdbedit -L 2>/dev/null')
    if (!stdout.trim()) return []
    return stdout.trim().split('\n').map(line => {
      const parts = line.split(':')
      return { username: parts[0], uid: parts[1], info: parts[2] }
    })
  } catch(e) { return [] }
}

async function addUser(username, password) {
  try {
    // Create system user
    try {
      await execAsync(`pw useradd ${username} -m -s /usr/sbin/nologin -g wheel`)
    } catch(e) { /* user may already exist */ }

    // Set samba password
    const { stdout, stderr } = await execAsync(
      `printf '%s\\n%s\\n' '${password}' '${password}' | smbpasswd -a -s ${username}`
    )
    return { success: true }
  } catch(e) {
    return { success: false, error: e.message }
  }
}

async function deleteUser(username) {
  try {
    await execAsync(`smbpasswd -x ${username}`)
    return { success: true }
  } catch(e) {
    return { success: false, error: e.message }
  }
}

async function getStatus() {
  try {
    const { stdout } = await execAsync('service samba_server status')
    return { running: stdout.includes('is running') }
  } catch(e) {
    return { running: false }
  }
}

module.exports = { getShares, addShare, deleteShare, getUsers, addUser, deleteUser, getStatus }
