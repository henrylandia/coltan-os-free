// Auth check — redirect to login if no token
const token = localStorage.getItem('coltan_token')
const user = JSON.parse(localStorage.getItem('coltan_user') || '{}')

if (!token) {
  window.location.href = '/login.html'
}

// Show logged in user
const usernameEl = document.getElementById('username')
if (usernameEl) usernameEl.textContent = user.username || 'admin'

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
    const res = await fetch('/api/health')
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

// Logout
function logout() {
  localStorage.removeItem('coltan_token')
  localStorage.removeItem('coltan_user')
  window.location.href = '/login.html'
}
