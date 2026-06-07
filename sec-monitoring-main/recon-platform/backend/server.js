const express = require('express');
const cors = require('cors');
const http = require('http');
const fs = require('fs');
const path = require('path');
const WebSocket = require('ws');
const alertEngine = require('./utils/alertEngine');

// Global error handlers to prevent unhandled stream errors (like Z_BUF_ERROR in Node 18 fetch) from crashing the server
process.on('uncaughtException', (err) => {
  console.error('[Uncaught Exception]', err);
});
process.on('unhandledRejection', (reason, promise) => {
  console.error('[Unhandled Rejection]', reason);
});

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(cors());
app.use(express.json());

// ── Persistent Storage ────────────────────────────────────────────────────────

const DATA_DIR  = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'scans.json');

// In-memory scan storage (populated from disk on startup)
const scans = new Map();
const clients = new Map(); // scanId → ws

// Monkeypatch global.fetch to add a hard Promise.race timeout. 
// Node 18's experimental fetch can hang forever if zlib throws a stream error.
const originalFetch = global.fetch;
global.fetch = function(url, options = {}) {
  const timeoutMs = 12000; // Hard max timeout to prevent infinite hangs
  return Promise.race([
    originalFetch(url, options),
    new Promise((_, reject) => setTimeout(() => reject(new Error('Hard fetch timeout (Z_BUF_ERROR prevention)')), timeoutMs))
  ]);
};

function loadScans() {
  try {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    if (fs.existsSync(DATA_FILE)) {
      const arr = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
      for (const scan of arr) {
        // Any scans that were mid-flight when server died get marked as error
        if (scan.status === 'running') {
          scan.status = 'error';
          scan.completedAt = new Date().toISOString();
          scan.error = 'Server restarted during scan';
          // Also mark any running modules as error to stop UI spinners
          if (scan.modules) {
            for (const key in scan.modules) {
              if (scan.modules[key].status === 'running') {
                scan.modules[key].status = 'error';
              }
            }
          }
        }
        scans.set(scan.id, scan);
      }
      console.log(`[Persistence] Loaded ${arr.length} scan(s) from disk.`);
    }
  } catch (err) {
    console.warn('[Persistence] Could not load scans from disk:', err.message);
  }
}

let _saveDebounce = null;
function saveScans() {
  // Debounce: coalesce rapid saves into one write after 1.5s quiet period
  if (_saveDebounce) clearTimeout(_saveDebounce);
  _saveDebounce = setTimeout(() => {
    try {
      if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
      const arr = Array.from(scans.values());
      fs.writeFileSync(DATA_FILE, JSON.stringify(arr, null, 2), 'utf8');
    } catch (err) {
      console.warn('[Persistence] Could not save scans to disk:', err.message);
    }
  }, 1500);
}

// Populate the in-memory Map from disk before routes are registered
loadScans();

// ── WebSocket ─────────────────────────────────────────────────────────────────

wss.on('connection', (ws, req) => {
  const scanId = new URL(req.url, 'ws://localhost').searchParams.get('scanId');
  if (scanId) {
    clients.set(scanId, ws);
    ws.on('close', () => clients.delete(scanId));
  }
});

// Broadcast progress to a specific scan's WebSocket client
function broadcast(scanId, data) {
  const ws = clients.get(scanId);
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(data));
  }
  // Persist whenever a scan finishes
  if (data.event === 'scan_complete' || data.event === 'module_complete') {
    saveScans();
  }
}

// Broadcast to ALL connected WebSocket clients (used for alerts)
function broadcastAll(data) {
  const payload = JSON.stringify(data);
  for (const ws of clients.values()) {
    if (ws && ws.readyState === WebSocket.OPEN) {
      try { ws.send(payload); } catch (_) {}
    }
  }
}

// ── Alert Engine ──────────────────────────────────────────────────────────────

alertEngine.init(broadcastAll);

// ── Routes ────────────────────────────────────────────────────────────────────

app.use('/api/scan',   require('./routes/scan')(scans, broadcast, alertEngine));
app.use('/api/report', require('./routes/report')(scans));
app.use('/api/alerts', require('./routes/alerts')());

// ── Start ─────────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log(`ReconScan API running on port ${PORT}`);
});
