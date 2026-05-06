'use strict'

const { exec } = require('child_process')
const { promisify } = require('util')
const execAsync = promisify(exec)
const fs = require('fs').promises

const UNBOUND_CONF = '/usr/local/etc/unbound/unbound.conf'
const BLOCKLIST_FILE = '/usr/local/etc/unbound/blocklists/blocklist.conf'
const BLOCKLIST_SCRIPT = '/usr/local/etc/unbound/update-blocklist.sh'
const SECURITY_FILE = '/usr/local/etc/coltan/security.json'
const UPDATE_LOG = '/usr/local/etc/unbound/var/log/unbound/blocklist-update.log'

async function ensureDir() {
  await execAsync('mkdir -p /usr/local/etc/coltan')
}

// ─── STATUS ───────────────────────────────────────────────────────────────────

async function getStatus() {
  const result = {
    unbound: { running: false, domains: 0 },
    clamav: { running: false, lastUpdate: null },
    suricata: { running: false }
  }

  // Unbound status
  try {
    const { stdout } = await execAsync('service unbound status 2>/dev/null')
    result.unbound.running = stdout.includes('is running')
  } catch(e) {}

  // Count blocked domains
  try {
    const { stdout } = await execAsync(`grep -c "local-zone" ${BLOCKLIST_FILE} 2>/dev/null || echo 0`)
    result.unbound.domains = parseInt(stdout.trim()) || 0
  } catch(e) {}

  // ClamAV status
  try {
    const { stdout } = await execAsync('service clamav-clamd status 2>/dev/null || pgrep clamd')
    result.clamav.running = stdout.trim().length > 0
  } catch(e) {}

  // Suricata status
  try {
    const { stdout } = await execAsync('pgrep suricata 2>/dev/null')
    result.suricata.running = stdout.trim().length > 0
  } catch(e) {}

  return result
}

// ─── SETTINGS ─────────────────────────────────────────────────────────────────

async function getSettings() {
  try {
    await ensureDir()
    const content = await fs.readFile(SECURITY_FILE, 'utf8')
    return JSON.parse(content)
  } catch(e) {
    return {
      dnsBlocker: {
        enabled: false,
        lists: {
          ads: true,
          malware: true,
          tracking: true,
          adult: false,
          gambling: false
        }
      },
      lastUpdate: null,
      whitelist: [],
      blacklist: []
    }
  }
}

async function saveSettings(settings) {
  await ensureDir()
  await fs.writeFile(SECURITY_FILE, JSON.stringify(settings, null, 2))
  return { success: true }
}

// ─── DNS BLOCKER ──────────────────────────────────────────────────────────────

async function enableDNSBlocker() {
  try {
    await execAsync('service unbound start 2>/dev/null || service unbound restart')
    const settings = await getSettings()
    settings.dnsBlocker.enabled = true
    await saveSettings(settings)
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

async function updateBlocklists(lists) {
  try {
    const settings = await getSettings()
    if (lists) settings.dnsBlocker.lists = lists

    // Build blocklist URLs based on selected lists
    const urls = []
    if (settings.dnsBlocker.lists.ads || settings.dnsBlocker.lists.tracking) {
      urls.push('https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts')
    }
    if (settings.dnsBlocker.lists.malware) {
      urls.push('https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts')
    }
    if (settings.dnsBlocker.lists.adult) {
      urls.push('https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts')
    }
    if (settings.dnsBlocker.lists.gambling) {
      urls.push('https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling/hosts')
    }

    settings.lastUpdate = new Date().toISOString()
    await saveSettings(settings)

    // Run update in background
    const urlList = urls.join(' ')
    const cmd = `(
      > /tmp/blocklist_temp.txt
      for url in ${urlList}; do
        fetch -q -o - "$url" 2>/dev/null | grep "^0\\.0\\.0\\.0" | awk '{print $2}' | grep -v "^0\\.0\\.0\\.0$" | grep -v "localhost" >> /tmp/blocklist_temp.txt
      done
      sort -u /tmp/blocklist_temp.txt > /tmp/blocklist_sorted.txt
      COUNT=$(wc -l < /tmp/blocklist_sorted.txt | tr -d ' ')
      echo "# Coltan OS DNS Blocklist - $(date)" > ${BLOCKLIST_FILE}
      echo "# Domains: $COUNT" >> ${BLOCKLIST_FILE}
      while IFS= read -r domain; do
        [ -z "$domain" ] && continue
        printf '    local-zone: "%s" redirect\\n' "$domain" >> ${BLOCKLIST_FILE}
        printf '    local-data: "%s A 0.0.0.0"\\n' "$domain" >> ${BLOCKLIST_FILE}
      done < /tmp/blocklist_sorted.txt
      rm -f /tmp/blocklist_temp.txt /tmp/blocklist_sorted.txt
      service unbound restart 2>/dev/null
      echo "[$(date)] Update complete - $COUNT domains" >> ${UPDATE_LOG}
    ) &`

    await execAsync(cmd)
    return { success: true, message: 'Blocklist update started in background' }
  } catch(e) { return { success: false, error: e.message } }
}

async function getUpdateLog() {
  try {
    const content = await fs.readFile(UPDATE_LOG, 'utf8')
    return content.split('\n').filter(Boolean).slice(-50).join('\n')
  } catch(e) { return 'No log available' }
}

// ─── WHITELIST / BLACKLIST ────────────────────────────────────────────────────

async function addToWhitelist(domain) {
  const settings = await getSettings()
  if (!settings.whitelist.includes(domain)) {
    settings.whitelist.push(domain)
    await saveSettings(settings)
    await applyWhitelistBlacklist()
  }
  return { success: true }
}

async function removeFromWhitelist(domain) {
  const settings = await getSettings()
  settings.whitelist = settings.whitelist.filter(d => d !== domain)
  await saveSettings(settings)
  await applyWhitelistBlacklist()
  return { success: true }
}

async function addToBlacklist(domain) {
  const settings = await getSettings()
  if (!settings.blacklist.includes(domain)) {
    settings.blacklist.push(domain)
    await saveSettings(settings)
    await applyWhitelistBlacklist()
  }
  return { success: true }
}

async function removeFromBlacklist(domain) {
  const settings = await getSettings()
  settings.blacklist = settings.blacklist.filter(d => d !== domain)
  await saveSettings(settings)
  await applyWhitelistBlacklist()
  return { success: true }
}

async function applyWhitelistBlacklist() {
  const settings = await getSettings()

  // Whitelist — local-zone passthrough
  let extraConf = '# Whitelist\n'
  for (const domain of settings.whitelist) {
    extraConf += `    local-zone: "${domain}" transparent\n`
  }

  // Blacklist — block extra domains
  extraConf += '\n# Custom Blacklist\n'
  for (const domain of settings.blacklist) {
    extraConf += `    local-zone: "${domain}" redirect\n`
    extraConf += `    local-data: "${domain} A 0.0.0.0"\n`
  }

  await fs.writeFile('/usr/local/etc/unbound/blocklists/custom.conf', extraConf)

  // Ensure custom.conf is included in unbound.conf
  const conf = await fs.readFile(UNBOUND_CONF, 'utf8')
  if (!conf.includes('custom.conf')) {
    const updated = conf.replace(
      'include: "/usr/local/etc/unbound/blocklists/blocklist.conf"',
      'include: "/usr/local/etc/unbound/blocklists/blocklist.conf"\n    include: "/usr/local/etc/unbound/blocklists/custom.conf"'
    )
    await fs.writeFile(UNBOUND_CONF, updated)
  }

  try { await execAsync('service unbound restart 2>/dev/null') } catch(e) {}
}

async function testDomain(domain) {
  try {
    const { stdout } = await execAsync(`host ${domain} 127.0.0.1 2>/dev/null`)
    const blocked = stdout.includes('0.0.0.0') || stdout.includes('NXDOMAIN')
    return { domain, blocked, response: stdout.trim() }
  } catch(e) { return { domain, blocked: false, error: e.message } }
}

module.exports = {
  getStatus, getSettings, saveSettings,
  enableDNSBlocker, disableDNSBlocker,
  updateBlocklists, getUpdateLog,
  addToWhitelist, removeFromWhitelist,
  addToBlacklist, removeFromBlacklist,
  testDomain
}

// ─── DNS STATS (Pi-hole style) ────────────────────────────────────────────────

async function getDNSStats() {
  try {
    const UNBOUND_LOG = '/usr/local/etc/unbound/var/log/unbound/unbound.log'
    const { stdout } = await execAsync(`tail -5000 ${UNBOUND_LOG} 2>/dev/null || echo ""`)
    if (!stdout.trim()) return { total: 0, blocked: 0, percent: 0, topDomains: [], topBlocked: [] }

    const lines = stdout.trim().split('\n').filter(l => l.includes(' info: '))
    const domainCount = {}
    const blockedDomains = {}
    let blocked = 0

    // Get blocked domains from blocklist
    let blocklistDomains = new Set()
    try {
      const { stdout: bl } = await execAsync(`grep "local-zone" ${BLOCKLIST_FILE} 2>/dev/null | awk '{print $2}' | tr -d '"' | head -200000`)
      bl.trim().split('\n').forEach(d => blocklistDomains.add(d.replace(/\.$/, '')))
    } catch(e) {}

    for (const line of lines) {
      const match = line.match(/info: [\d\.:a-f]+ (.+?)\. [A-Z]+ IN/)
      if (!match) continue
      const domain = match[1].toLowerCase()
      if (domain === 'localhost' || domain === '') continue
      domainCount[domain] = (domainCount[domain] || 0) + 1
      // Check if blocked (resolved to 0.0.0.0)
      if (blocklistDomains.has(domain)) {
        blocked++
        blockedDomains[domain] = (blockedDomains[domain] || 0) + 1
      }
    }

    const total = lines.length
    const percent = total > 0 ? ((blocked / total) * 100).toFixed(1) : 0
    const topDomains = Object.entries(domainCount).sort((a,b) => b[1]-a[1]).slice(0,10).map(([domain, count]) => ({ domain, count }))
    const topBlocked = Object.entries(blockedDomains).sort((a,b) => b[1]-a[1]).slice(0,10).map(([domain, count]) => ({ domain, count }))

    return { total, blocked, percent: parseFloat(percent), topDomains, topBlocked }
  } catch(e) { return { total: 0, blocked: 0, percent: 0, topDomains: [], topBlocked: [] } }
}

module.exports.getDNSStats = getDNSStats
