// Auth check
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

// Fetch real metrics from backend
async function fetchMetrics() {
  try {
    const res = await fetch('/api/metrics', {
      headers: { 'Authorization': `Bearer ${token}` }
    })

    if (res.status === 401) {
      localStorage.removeItem('coltan_token')
      window.location.href = '/login.html'
      return
    }

    const data = await res.json()

    document.getElementById('cpu').textContent = data.cpu
    document.getElementById('memory').textContent = data.memory
    document.getElementById('disk').textContent = data.disk
    document.getElementById('uptime').textContent = data.uptime

  } catch(e) {
    console.error('Error fetching metrics:', e)
  }
}

setInterval(fetchMetrics, 5000)
fetchMetrics()

// Logout
function logout() {
  localStorage.removeItem('coltan_token')
  localStorage.removeItem('coltan_user')
  window.location.href = '/login.html'
}
