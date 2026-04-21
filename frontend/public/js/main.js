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

// WebSocket connection
function connectWS() {
  const ws = new WebSocket(`ws://192.168.1.210:3000/ws/metrics`)

  ws.onopen = () => {
    console.log('WebSocket connected')
    document.querySelector('.status-dot').style.background = '#22c55e'
  }

  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data)
      if (msg.type === 'metrics') {
        const d = msg.data
        document.getElementById('cpu').textContent = d.cpu
        document.getElementById('memory').textContent = d.memory
        document.getElementById('disk').textContent = d.disk
        document.getElementById('uptime').textContent = d.uptime
      }
    } catch(e) {
      console.error('Error parsing WS message:', e)
    }
  }

  ws.onclose = () => {
    console.log('WebSocket disconnected, reconnecting in 3s...')
    document.querySelector('.status-dot').style.background = '#ef4444'
    setTimeout(connectWS, 3000)
  }

  ws.onerror = (err) => {
    console.error('WebSocket error:', err)
    ws.close()
  }
}

connectWS()

// Logout
function logout() {
  localStorage.removeItem('coltan_token')
  localStorage.removeItem('coltan_user')
  window.location.href = '/login.html'
}
