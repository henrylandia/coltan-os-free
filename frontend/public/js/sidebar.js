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
        <a href="/pages/fileserver.html" class="nav-item ${activePage === 'fileserver' ? 'active' : ''}">
          <i class="bi bi-hdd-stack"></i> File Server
        </a>
        <a href="/pages/backup.html" class="nav-item ${activePage === 'backup' ? 'active' : ''}">
          <i class="bi bi-cloud-arrow-up"></i> Backup
        </a>
        <a href="/pages/console.html" class="nav-item ${activePage === 'console' ? 'active' : ''}">
          <i class="bi bi-terminal"></i> Console
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
