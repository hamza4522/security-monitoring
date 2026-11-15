const express = require('express');
const cors = require('cors');
const http = require('http');
const fs = require('fs');
const path = require('path');
const WebSocket = require('ws');
const alertEngine = require('./utils/alertEngine');

// ── Graceful shutdown on fatal errors ────────────────────────────────────────
// Do NOT silently swallow uncaughtException — the process may be in a corrupt
// state. Log it and exit so the process manager (Docker, PM2) can restart cleanly.
process.on('uncaughtException', (err) => {
  // Ignore known benign Z_BUF_ERROR from Node 18 experimental fetch streams
  if (err.code === 'Z_BUF_ERROR') return;
  console.error('[Fatal – Uncaught Exception]', err);
  process.exit(1);
});
process.on('unhandledRejection', (reason) => {
  console.error('[Unhandled Rejection]', reason);
  // Don't exit — rejections are often from individual scan HTTP errors
});

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// ── CORS — restrict to the configured frontend origin ─────────────────────────
const ALLOWED_ORIGIN = process.env.FRONTEND_ORIGIN || 'http://localhost:3000';
app.use(cors({ origin: ALLOWED_ORIGIN, optionsSuccessStatus: 200 }));
app.use(express.json());

// ── API Key Authentication Middleware ─────────────────────────────────────────
// Set API_KEY in your .env (or leave unset to disable auth in dev).
const API_KEY = process.env.API_KEY || '';
if (API_KEY) {
  app.use('/api', (req, res, next) => {
    const provided = req.headers['x-api-key'] || req.query.apiKey || '';
    if (provided !== API_KEY) {
      return res.status(401).json({ error: 'Unauthorized: missing or invalid API key.' });
    }
    next();
  });
} else {
  console.warn('[Auth] API_KEY not set — all /api routes are unauthenticated. Set API_KEY in .env for production.');
}

// ── Persistent Storage ────────────────────────────────────────────────────────

const DATA_DIR  = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'scans.json');

// In-memory scan storage (populated from disk on startup)
const scans = new Map();
const clients = new Map(); // scanId → ws

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

// ── Scan Retention Cap ────────────────────────────────────────────────────────
// Keep only the most recent 500 completed scans to prevent unbounded memory/disk growth.
const MAX_STORED_SCANS = 500;

function enforceRetentionCap() {
  if (scans.size <= MAX_STORED_SCANS) return;
  const sorted = Array.from(scans.values())
    .sort((a, b) => new Date(b.startedAt) - new Date(a.startedAt));
  const toRemove = sorted.slice(MAX_STORED_SCANS);
  for (const scan of toRemove) scans.delete(scan.id);
  console.log(`[Retention] Pruned ${toRemove.length} old scan(s). Keeping ${scans.size}.`);
}

// Populate the in-memory Map from disk before routes are registered
loadScans();
enforceRetentionCap();

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
  // Only persist to disk when the scan finishes — not on every module_complete
  // (module_complete fires 20x per scan and serialises the full scans.json each time)
  if (data.event === 'scan_complete') {
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

// ── Health Endpoint ───────────────────────────────────────────────────────────
// Exempt from API_KEY auth — used by Docker healthcheck and load balancers.
app.get('/health', (req, res) => res.json({
  status: 'ok',
  uptime: Math.floor(process.uptime()),
  scans: scans.size,
  ts: new Date().toISOString(),
}));

// ── Routes ────────────────────────────────────────────────────────────────────

app.use('/api/scan',   require('./routes/scan')(scans, broadcast, alertEngine));
app.use('/api/report', require('./routes/report')(scans));
app.use('/api/alerts', require('./routes/alerts')());

// ── Start ─────────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log(`ReconScan API running on port ${PORT}`);
});
