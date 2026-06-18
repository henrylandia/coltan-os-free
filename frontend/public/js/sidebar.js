
// Interceptor global — detecta 401 y redirige al login, detecta 403 de licencia
const _originalFetch = window.fetch
window.fetch = async function(...args) {
  const res = await _originalFetch(...args)
  if (res.status === 401) {
    localStorage.removeItem('coltan_token')
    localStorage.removeItem('coltan_user')
    window.location.href = '/login.html'
    return res
  }
  if (res.status === 403) {
    const clone = res.clone()
    try {
      const data = await clone.json()
      if (data.feature === 'premium') {
        showPremiumModal(data.message)
      }
    } catch(e) {}
  }
  return res
}

function showPremiumModal(message) {
  if (document.getElementById('coltan-premium-modal')) return
  const modal = document.createElement('div')
  modal.id = 'coltan-premium-modal'
  modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:99999;display:flex;align-items:center;justify-content:center'
  modal.innerHTML = `
    <div style="background:var(--bg-card,#1a1d2e);border:1px solid var(--border,#2d3148);border-radius:16px;padding:32px;max-width:420px;text-align:center">
      <div style="font-size:2.5rem;color:#f59e0b;margin-bottom:12px"><i class="bi bi-star-fill"></i></div>
      <div style="font-size:1.1rem;font-weight:700;color:#e2e8f0;margin-bottom:8px">Función Premium</div>
      <div style="font-size:0.85rem;color:#94a3b8;margin-bottom:24px">${message || 'Esta función requiere una licencia activa de Coltan OS Premium.'}</div>
      <div style="display:flex;gap:8px;justify-content:center">
        <button onclick="document.getElementById('coltan-premium-modal').remove()" style="background:rgba(100,116,139,0.15);border:1px solid #2d3148;color:#94a3b8;padding:8px 18px;border-radius:8px;cursor:pointer;font-size:0.85rem">Cerrar</button>
        <a href="/pages/settings.html" style="background:#4f8ef7;color:white;padding:8px 18px;border-radius:8px;text-decoration:none;font-size:0.85rem;font-weight:600">Activar Licencia</a>
      </div>
    </div>`
  document.body.appendChild(modal)
}

function loadSidebar(activePage) {
  const sidebar = `
    <div class="sidebar">
      <div class="sidebar-brand">
        <i class="bi bi-cpu"></i>
        <span>Coltan OS</span>
      </div>
      <nav class="sidebar-nav">
        <a href="/" class="nav-item ${activePage === 'dashboard' ? 'active' : ''}">
          <i class="bi bi-speedometer2"></i> Dashboard
        </a>
        <a href="/pages/networking.html" class="nav-item ${activePage === 'networking' ? 'active' : ''}">
          <i class="bi bi-ethernet"></i> Networking
        </a>
        <a href="/pages/firewall.html" class="nav-item ${activePage === 'firewall' ? 'active' : ''}">
          <i class="bi bi-shield-check"></i> Firewall
        </a>
        <a href="/pages/sites.html" class="nav-item ${activePage === 'sites' ? 'active' : ''}">
          <i class="bi bi-shield-x"></i> Site Blocking
        </a>
        <a href="/pages/security.html" class="nav-item ${activePage === 'security' ? 'active' : ''}">
          <i class="bi bi-shield-fill"></i> Security
        </a>
        <a href="/pages/qos.html" class="nav-item ${activePage === 'qos' ? 'active' : ''}">
          <i class="bi bi-speedometer"></i> QoS
        </a>
        <div class="nav-group">
          <div class="nav-group-title"><i class="bi bi-lock"></i> VPN</div>
          <a href="/pages/wireguard.html" class="nav-item nav-sub ${activePage === 'wireguard' ? 'active' : ''}">
            <i class="bi bi-shield-lock"></i> WireGuard
          </a>
          <a href="/pages/openvpn.html" class="nav-item nav-sub ${activePage === 'openvpn' ? 'active' : ''}">
            <i class="bi bi-lock-fill"></i> OpenVPN
          </a>
        </div>
        <a href="/pages/backup.html" class="nav-item ${activePage === 'backup' ? 'active' : ''}">
          <i class="bi bi-cloud-arrow-up"></i> Backup
        </a>
        <a href="/pages/reports.html" class="nav-item ${activePage === 'reports' ? 'active' : ''}">
          <i class="bi bi-file-bar-graph"></i> Reportes
        </a>
        <a href="/pages/settings.html" class="nav-item ${activePage === 'settings' ? 'active' : ''}">
          <i class="bi bi-gear"></i> Settings
        </a>
      </nav>
    </div>
  `
  document.body.insertAdjacentHTML('afterbegin', sidebar)
}
function loadTopbar(title) {
  const user = JSON.parse(localStorage.getItem('coltan_user') || '{}')
  const topbar = `
    <div class="topbar">
      <div class="topbar-title">${title}</div>
      <div class="topbar-info">
        <span class="status-dot online"></span>
        <span id="username">${user.username || 'admin'}</span>
        <span class="ms-3" id="clock"></span>
        <button onclick="logout()" class="ms-3 btn btn-sm" style="background:#2d3148;color:#e2e8f0;border:none;border-radius:6px;padding:4px 12px;font-size:0.8rem;">
          <i class="bi bi-box-arrow-right"></i> Logout
        </button>
      </div>
    </div>
  `
  document.querySelector('.main-content').insertAdjacentHTML('afterbegin', topbar)
}
function logout() {
  localStorage.removeItem('coltan_token')
  localStorage.removeItem('coltan_user')
  window.location.href = '/login.html'
}
function startClock() {
  function update() {
    const el = document.getElementById('clock')
    if (el) el.textContent = new Date().toLocaleTimeString()
  }
  setInterval(update, 1000)
  update()
}
