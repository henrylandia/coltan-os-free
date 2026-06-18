'use strict'
const Database = require('better-sqlite3')
const path = require('path')

const DB_PATH = '/var/db/coltanos/analytics.db'

let db

function getDB() {
  if (!db) {
    db = new Database(DB_PATH)
    db.pragma('journal_mode = WAL')
    db.pragma('foreign_keys = ON')
    initSchema()
  }
  return db
}

function initSchema() {
  db.exec(`
    -- Tráfico por interfaz (muestra cada minuto)
    CREATE TABLE IF NOT EXISTS traffic_samples (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      interface TEXT NOT NULL,
      rx_bytes INTEGER NOT NULL DEFAULT 0,
      tx_bytes INTEGER NOT NULL DEFAULT 0,
      rx_delta INTEGER NOT NULL DEFAULT 0,
      tx_delta INTEGER NOT NULL DEFAULT 0,
      sampled_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_traffic_iface_time ON traffic_samples(interface, sampled_at);

    -- DNS queries (sitios visitados)
    CREATE TABLE IF NOT EXISTS dns_queries (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      domain TEXT NOT NULL,
      client_ip TEXT NOT NULL,
      query_type TEXT DEFAULT 'A',
      queried_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_dns_domain ON dns_queries(domain);
    CREATE INDEX IF NOT EXISTS idx_dns_client ON dns_queries(client_ip);
    CREATE INDEX IF NOT EXISTS idx_dns_time ON dns_queries(queried_at);

    -- Accesos al panel web
    CREATE TABLE IF NOT EXISTS panel_access_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT,
      ip TEXT,
      method TEXT,
      endpoint TEXT,
      status_code INTEGER,
      response_time REAL,
      accessed_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_panel_user ON panel_access_log(username);
    CREATE INDEX IF NOT EXISTS idx_panel_time ON panel_access_log(accessed_at);

    -- Sesiones VPN
    CREATE TABLE IF NOT EXISTS vpn_sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      vpn_type TEXT NOT NULL,
      peer_id TEXT,
      username TEXT,
      client_ip TEXT,
      bytes_rx INTEGER DEFAULT 0,
      bytes_tx INTEGER DEFAULT 0,
      connected_at INTEGER NOT NULL,
      disconnected_at INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_vpn_time ON vpn_sessions(connected_at);

    -- Log de ataques (desde Suricata + autoblock)
    CREATE TABLE IF NOT EXISTS attack_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      src_ip TEXT NOT NULL,
      country TEXT,
      country_code TEXT,
      city TEXT,
      isp TEXT,
      attack_type TEXT,
      severity TEXT,
      signature TEXT,
      proto TEXT,
      dest_port INTEGER,
      blocked INTEGER DEFAULT 0,
      detected_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_attack_ip ON attack_log(src_ip);
    CREATE INDEX IF NOT EXISTS idx_attack_time ON attack_log(detected_at);
    CREATE INDEX IF NOT EXISTS idx_attack_country ON attack_log(country_code);
  `)
  console.log('[DB] Schema inicializado en', DB_PATH)
}

module.exports = { getDB }
