const token = localStorage.getItem('coltan_token')
if (!token) window.location.href = '/login.html'

function connectWS() {
  const ws = new WebSocket(`ws://192.168.1.210:3000/ws/metrics`)

  ws.onopen = () => {
    const dot = document.querySelector('.status-dot')
    if (dot) dot.style.background = '#22c55e'
  }

  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data)
      if (msg.type === 'metrics') {
        const d = msg.data
        const cpu = document.getElementById('cpu')
        const memory = document.getElementById('memory')
        const disk = document.getElementById('disk')
        const uptime = document.getElementById('uptime')
        if (cpu) cpu.textContent = d.cpu
        if (memory) memory.textContent = d.memory
        if (disk) disk.textContent = d.disk
        if (uptime) uptime.textContent = d.uptime
      }
    } catch(e) {}
  }

  ws.onclose = () => {
    const dot = document.querySelector('.status-dot')
    if (dot) dot.style.background = '#ef4444'
    setTimeout(connectWS, 3000)
  }

  ws.onerror = () => ws.close()
}

async function loadDashboard() {
  try {
    const res = await fetch('/api/dashboard', {
      headers: { 'Authorization': `Bearer ${token}` }
    })

    if (res.status === 401) {
      localStorage.removeItem('coltan_token')
      window.location.href = '/login.html'
      return
    }

    const data = await res.json()
    const m = data.modules

    // Firewall
    const fwEl = document.getElementById('fw-status')
    const fwSub = document.getElementById('fw-sub')
    if (fwEl) {
      fwEl.textContent = m.firewall.enabled ? 'Enabled' : 'Disabled'
      fwEl.className = `module-status status-${m.firewall.enabled ? 'online' : 'disabled'}`
      if (fwSub) fwSub.textContent = `${m.firewall.states} active states`
    }

    // File Server
    const fsEl = document.getElementById('fs-status')
    const fsSub = document.getElementById('fs-sub')
    if (fsEl) {
      fsEl.textContent = m.fileserver.status === 'online' ? 'Online' : 'Offline'
      fsEl.className = `module-status status-${m.fileserver.status === 'online' ? 'online' : 'offline'}`
      if (fsSub) fsSub.textContent = `${m.fileserver.totalPools} pool · ${m.fileserver.totalSnapshots} snapshots`
    }

    // Backup
    const bkEl = document.getElementById('bk-status')
    const bkSub = document.getElementById('bk-sub')
    if (bkEl) {
      if (m.backup.status === 'warning') {
        bkEl.textContent = 'Warning'
        bkEl.className = 'module-status status-warning'
        if (bkSub) bkSub.textContent = `${m.backup.failedPolicies} failed policies`
      } else if (m.backup.status === 'none') {
        bkEl.textContent = 'No policies'
        bkEl.className = 'module-status status-none'
        if (bkSub) bkSub.textContent = 'Create a backup policy'
      } else {
        bkEl.textContent = 'OK'
        bkEl.className = 'module-status status-online'
        if (bkSub) bkSub.textContent = `${m.backup.activePolicies} active policies`
      }
    }

    // Settings sub
    const settingsSub = document.getElementById('settings-sub')
    if (settingsSub && data.metrics) {
      settingsSub.textContent = `Uptime: ${data.metrics.uptime}`
    }

  } catch(e) {
    console.error('Dashboard error:', e)
  }
}

document.addEventListener('DOMContentLoaded', () => {
  connectWS()
  loadDashboard()
  setInterval(loadDashboard, 15000)
})
