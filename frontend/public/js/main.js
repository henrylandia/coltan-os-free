const token = localStorage.getItem('coltan_token')
if (!token) window.location.href = '/login.html'

// Firewall status
async function loadFirewallStatus() {
  try {
    const res = await fetch('/api/firewall/status', {
      headers: { 'Authorization': `Bearer ${token}` }
    })
    const data = await res.json()
    const el = document.getElementById('fw-status')
    if (el) {
      el.textContent = data.enabled ? 'Enabled' : 'Disabled'
      el.style.color = data.enabled ? '#22c55e' : '#ef4444'
    }
  } catch(e) {}
}

// WebSocket for metrics
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

// Start everything after DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  connectWS()
  loadFirewallStatus()
  setInterval(loadFirewallStatus, 10000)
})
