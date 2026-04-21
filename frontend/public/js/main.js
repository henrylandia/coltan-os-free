// Clock
function updateClock() {
  const now = new Date()
  document.getElementById('clock').textContent = now.toLocaleTimeString()
}
setInterval(updateClock, 1000)
updateClock()

// Fetch stats from backend
async function fetchStats() {
  try {
    const res = await fetch('http://192.168.1.210:3000/health')
    const data = await res.json()
    const uptime = Math.floor(data.uptime)
    const h = Math.floor(uptime / 3600)
    const m = Math.floor((uptime % 3600) / 60)
    const s = uptime % 60
    document.getElementById('uptime').textContent = `${h}h ${m}m ${s}s`
  } catch(e) {
    document.getElementById('uptime').textContent = 'error'
  }
}
setInterval(fetchStats, 5000)
fetchStats()
