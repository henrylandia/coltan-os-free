'use strict'

const { exec } = require('child_process')
const { promisify } = require('util')
const execAsync = promisify(exec)
const fs = require('fs').promises
const dns = require('dns').promises

const SITES_FILE = '/usr/local/etc/coltan/blocked-sites.json'
const GROUPS_FILE = '/usr/local/etc/coltan/blocked-groups.json'
const CATEGORIES_FILE = '/usr/local/etc/coltan/custom-categories.json'

async function ensureDir() {
  await execAsync('mkdir -p /usr/local/etc/coltan')
}

// ─── CATEGORIAS ───────────────────────────────────────────────────────────────

const DEFAULT_CATEGORIES = {
  streaming_music: {
    name: 'Streaming Música', icon: '🎵',
    domains: ['spotify.com','scdn.co','spotifycdn.com','music.apple.com','itunes.apple.com','deezer.com','dzcdn.net','tidal.com','soundcloud.com','pandora.com','last.fm']
  },
  streaming_video: {
    name: 'Streaming Video', icon: '📺',
    domains: ['youtube.com','youtu.be','googlevideo.com','ytimg.com','netflix.com','nflxvideo.net','nflximg.net','twitch.tv','twitchapps.com','jtvnw.net','primevideo.com','disneyplus.com','hulu.com','hbomax.com','max.com','paramountplus.com']
  },
  social_media: {
    name: 'Redes Sociales', icon: '📱',
    domains: ['facebook.com','fbcdn.net','facebook.net','instagram.com','cdninstagram.com','tiktok.com','tiktokcdn.com','tiktokv.com','twitter.com','x.com','twimg.com','reddit.com','redd.it','redditmedia.com','snapchat.com','linkedin.com']
  },
  gaming: {
    name: 'Gaming', icon: '🎮',
    domains: ['steampowered.com','steamcontent.com','steam-chat.com','epicgames.com','unrealengine.com','xbox.com','xboxlive.com','playstation.com','psn.com','battle.net','blizzard.com','riotgames.com','leagueoflegends.com']
  },
  gambling: {
    name: 'Apuestas', icon: '🎰',
    domains: ['bet365.com','pokerstars.com','888casino.com','betway.com','williamhill.com','draftkings.com','fanduel.com','unibet.com','bwin.com','codere.com','betsson.com','interwetten.com']
  },
  adult: {
    name: 'Contenido Adulto', icon: '🔞',
    domains: ['pornhub.com','xvideos.com','xnxx.com','xhamster.com','redtube.com','youporn.com','brazzers.com','onlyfans.com','chaturbate.com','livejasmin.com','cam4.com','stripchat.com']
  },
  torrents: {
    name: 'Torrents / P2P', icon: '🏴‍☠️',
    domains: ['thepiratebay.org','tpb.party','1337x.to','rarbg.to','nyaa.si','rutracker.org','kickasstorrents.to','torrentz2.eu','yts.mx','eztv.re','limetorrents.cc','torrentgalaxy.to']
  },
  network_abuse: {
    name: 'Abuso de Red', icon: '⚠️',
    domains: ['speedtest.net','fast.com','testmy.net','dropbox.com','wetransfer.com','sendspace.com','zippyshare.com','uploadfiles.io','gofile.io']
  }
}

async function getCategories() {
  try {
    const content = await fs.readFile(CATEGORIES_FILE, 'utf8')
    const custom = JSON.parse(content)
    return { ...DEFAULT_CATEGORIES, ...custom }
  } catch(e) { return { ...DEFAULT_CATEGORIES } }
}

async function saveCustomCategories(categories) {
  await ensureDir()
  // Only save non-default categories and overrides
  const custom = {}
  for (const [id, cat] of Object.entries(categories)) {
    custom[id] = cat
  }
  await fs.writeFile(CATEGORIES_FILE, JSON.stringify(custom, null, 2))
}

async function updateCategory(id, data) {
  const cats = await getCategories()
  if (!cats[id]) return { success: false, error: 'Category not found' }
  cats[id] = { ...cats[id], ...data }

  // Save to custom file
  let custom = {}
  try { custom = JSON.parse(await fs.readFile(CATEGORIES_FILE, 'utf8')) } catch(e) {}
  custom[id] = cats[id]
  await fs.writeFile(CATEGORIES_FILE, JSON.stringify(custom, null, 2))
  return { success: true }
}

async function createCategory(data) {
  const id = 'custom_' + Date.now()
  let custom = {}
  try { custom = JSON.parse(await fs.readFile(CATEGORIES_FILE, 'utf8')) } catch(e) {}
  custom[id] = {
    name: data.name,
    icon: data.icon || '🔒',
    domains: data.domains || [],
    custom: true
  }
  await ensureDir()
  await fs.writeFile(CATEGORIES_FILE, JSON.stringify(custom, null, 2))
  return { success: true, id, category: custom[id] }
}

async function deleteCategory(id) {
  let custom = {}
  try { custom = JSON.parse(await fs.readFile(CATEGORIES_FILE, 'utf8')) } catch(e) {}
  delete custom[id]
  await fs.writeFile(CATEGORIES_FILE, JSON.stringify(custom, null, 2))
  return { success: true }
}

// ─── GROUPS ───────────────────────────────────────────────────────────────────

async function getGroups() {
  try {
    await ensureDir()
    const content = await fs.readFile(GROUPS_FILE, 'utf8')
    return JSON.parse(content)
  } catch(e) { return [] }
}

async function saveGroups(groups) {
  await ensureDir()
  await fs.writeFile(GROUPS_FILE, JSON.stringify(groups, null, 2))
}

async function resolveDomain(domain) {
  try {
    const result = await dns.resolve4(domain)
    return result
  } catch(e) { return [] }
}

async function createGroup(data) {
  const groups = await getGroups()

  // Resolve domains
  const entries = []
  for (const entry of (data.entries || [])) {
    let resolvedIPs = []
    if (entry.type === 'domain') {
      try { resolvedIPs = await resolveDomain(entry.value) } catch(e) {}
    }
    entries.push({ ...entry, resolvedIPs, id: Date.now().toString() + Math.random().toString(36).substr(2,4) })
    await new Promise(r => setTimeout(r, 50))
  }

  const group = {
    id: Date.now().toString(),
    name: data.name,
    description: data.description || '',
    categoryId: data.categoryId || 'custom',
    applyTo: data.applyTo || 'all',
    applyToValue: data.applyToValue || '',
    enabled: true,
    entries,
    createdAt: new Date().toISOString()
  }

  groups.push(group)
  await saveGroups(groups)
  await applyBlocking()
  return { success: true, group }
}

async function deleteGroup(id) {
  const groups = await getGroups()
  const filtered = groups.filter(g => g.id !== id)
  await saveGroups(filtered)
  await applyBlocking()
  return { success: true }
}

async function toggleGroup(id) {
  const groups = await getGroups()
  const group = groups.find(g => g.id === id)
  if (!group) return { success: false, error: 'Group not found' }
  group.enabled = !group.enabled
  await saveGroups(groups)
  await applyBlocking()
  return { success: true, enabled: group.enabled }
}

async function addEntryToGroup(groupId, entry) {
  const groups = await getGroups()
  const group = groups.find(g => g.id === groupId)
  if (!group) return { success: false, error: 'Group not found' }

  let resolvedIPs = []
  if (entry.type === 'domain') {
    try { resolvedIPs = await resolveDomain(entry.value) } catch(e) {}
  }

  group.entries.push({
    id: Date.now().toString(),
    type: entry.type || 'domain',
    value: entry.value,
    resolvedIPs
  })

  await saveGroups(groups)
  await applyBlocking()
  return { success: true }
}

async function removeEntryFromGroup(groupId, entryId) {
  const groups = await getGroups()
  const group = groups.find(g => g.id === groupId)
  if (!group) return { success: false, error: 'Group not found' }
  group.entries = group.entries.filter(e => e.id !== entryId)
  await saveGroups(groups)
  await applyBlocking()
  return { success: true }
}

async function createGroupFromCategory(categoryId, name, applyTo, applyToValue) {
  const cats = await getCategories()
  const cat = cats[categoryId]
  if (!cat) return { success: false, error: 'Category not found' }

  const entries = cat.domains.map(d => ({ type: 'domain', value: d, resolvedIPs: [] }))

  return await createGroup({
    name: name || cat.name,
    description: `${cat.icon} ${cat.name}`,
    categoryId,
    applyTo: applyTo || 'all',
    applyToValue: applyToValue || '',
    entries
  })
}

async function refreshDNS() {
  const groups = await getGroups()
  let updated = 0
  for (const group of groups) {
    for (const entry of group.entries) {
      if (entry.type === 'domain') {
        try {
          entry.resolvedIPs = await resolveDomain(entry.value)
          updated++
        } catch(e) {}
        await new Promise(r => setTimeout(r, 50))
      }
    }
  }
  await saveGroups(groups)
  await applyBlocking()
  return { success: true, updated }
}

// ─── PF BLOCKING ──────────────────────────────────────────────────────────────

async function applyBlocking() {
  const groups = await getGroups()
  const enabledGroups = groups.filter(g => g.enabled)

  let anchorConf = `# Coltan OS — Sites blocking anchor\n`
  const allIPs = new Set()
  const perRules = []

  for (const group of enabledGroups) {
    const ips = []
    for (const entry of group.entries) {
      if (entry.type === 'ip') ips.push(entry.value)
      else if (entry.type === 'range') ips.push(entry.value)
      else if (entry.type === 'domain' && entry.resolvedIPs) {
        entry.resolvedIPs.forEach(ip => ips.push(ip))
      }
    }

    if (ips.length === 0) continue

    if (group.applyTo === 'all') {
      ips.forEach(ip => allIPs.add(ip))
    } else {
      perRules.push({ group, ips })
    }
  }

  if (allIPs.size > 0) {
    anchorConf += `table <blocked_sites> { ${Array.from(allIPs).join(', ')} }\n`
    anchorConf += `block in quick from any to <blocked_sites>\n`
    anchorConf += `block out quick from any to <blocked_sites>\n`
    anchorConf += `block in quick from <blocked_sites> to any\n`
  }

  for (const { group, ips } of perRules) {
    const ipList = ips.join(', ')
    if (group.applyTo === 'interface') {
      anchorConf += `block in quick on ${group.applyToValue} from any to { ${ipList} }\n`
      anchorConf += `block out quick on ${group.applyToValue} to { ${ipList} }\n`
    } else if (group.applyTo === 'ip' || group.applyTo === 'range') {
      anchorConf += `block out quick from ${group.applyToValue} to { ${ipList} }\n`
    }
  }

  await fs.writeFile('/etc/pf.sites.conf', anchorConf)
  try { await execAsync('pfctl -a coltan/sites -f /etc/pf.sites.conf 2>/dev/null') } catch(e) {}

  return { success: true, blockedIPs: allIPs.size }
}

async function getStats() {
  const groups = await getGroups()
  const enabled = groups.filter(g => g.enabled).length
  const totalEntries = groups.reduce((a, g) => a + g.entries.length, 0)
  return { totalGroups: groups.length, enabledGroups: enabled, totalEntries }
}

module.exports = {
  getCategories, updateCategory, createCategory, deleteCategory,
  getGroups, createGroup, deleteGroup, toggleGroup,
  addEntryToGroup, removeEntryFromGroup,
  createGroupFromCategory, refreshDNS, applyBlocking, getStats
}
