import { useState, useEffect, useRef, useCallback } from "react";
import {
  RadarChart, Radar, PolarGrid, PolarAngleAxis,
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
  LineChart, Line, CartesianGrid
} from "recharts";
import "./App.css";

const API_BASE = process.env.REACT_APP_API_URL || `http://${window.location.hostname}:3001/api`;
const WS_BASE = process.env.REACT_APP_WS_URL || `ws://${window.location.hostname}:3001`;

// ── Severity helpers ─────────────────────────────────────────────────────────
const SEVERITY_CONFIG = {
  critical: { label: "Critical", color: "#e11d48", bg: "#fff1f2", text: "#9f1239" },
  high: { label: "High", color: "#ea580c", bg: "#fff7ed", text: "#9a3412" },
  medium: { label: "Medium", color: "#d97706", bg: "#fffbeb", text: "#92400e" },
  low: { label: "Low", color: "#16a34a", bg: "#f0fdf4", text: "#14532d" },
  info: { label: "Info", color: "#0284c7", bg: "#f0f9ff", text: "#0c4a6e" },
};
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// ── Toast System ──────────────────────────────────────────────────────────────
let _toastSetter = null;
function showToast(message, type = "info", duration = 5000) {
  if (_toastSetter) _toastSetter(prev => [
    { id: Date.now() + Math.random(), message, type, duration }, ...prev
  ]);
}

function ToastContainer() {
  const [toasts, setToasts] = useState([]);
  _toastSetter = setToasts;
  const dismiss = (id) => setToasts(p => p.filter(t => t.id !== id));
  useEffect(() => {
    if (!toasts.length) return;
    const t = toasts[toasts.length - 1];
    const timer = setTimeout(() => dismiss(t.id), t.duration || 5000);
    return () => clearTimeout(timer);
  }, [toasts]);
  return (
    <div className="toast-container">
      {toasts.map(t => (
        <div key={t.id} className={`toast toast-${t.type}`}>
          <span className="toast-icon">
            {t.type === "success" ? "✅" : t.type === "error" ? "🔴" : t.type === "warning" ? "⚠️" : "🔔"}
          </span>
          <span className="toast-message">{t.message}</span>
          <button className="toast-close" onClick={() => dismiss(t.id)}>×</button>
        </div>
      ))}
    </div>
  );
}

// ── Clipboard helper ──────────────────────────────────────────────────────────
function copyText(text) {
  navigator.clipboard.writeText(text).then(() => showToast("Copied to clipboard!", "success", 2000));
}

function SeverityBadge({ severity }) {
  const c = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.info;
  return (
    <span className="severity-badge" style={{ background: c.bg, color: c.text, border: `1px solid ${c.color}30` }}>
      {c.label}
    </span>
  );
}

function StatusDot({ status }) {
  const colors = { complete: "#16a34a", running: "#0284c7", error: "#e11d48", pending: "#9ca3af", cancelled: "#9ca3af" };
  return <span className="status-dot" style={{ background: colors[status] || "#9ca3af" }} />;
}

// ── Main App ─────────────────────────────────────────────────────────────────
export default function App() {
  const [view, setView] = useState("dashboard");
  const [scans, setScans] = useState([]);
  const [activeScan, setActiveScan] = useState(null);
  const [activeTab, setActiveTab] = useState("overview");
  const [scanLog, setScanLog] = useState([]);
  const [theme, setTheme] = useState(() => localStorage.getItem("theme") || "dark");
  const [searchOpen, setSearchOpen] = useState(false);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const [alertHistory, setAlertHistory] = useState([]);
  const [unreadAlerts, setUnreadAlerts] = useState(0);
  const [compareIds, setCompareIds] = useState([]); // up to 2 scan IDs for comparison
  const wsRef = useRef(null);
  const domainInputRef = useRef(null);

  const fetchScans = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/scan`);
      const data = await res.json();
      setScans(data);
    } catch (_) { }
  }, []);

  const fetchActiveScanDetails = useCallback(async (scanId) => {
    try {
      const res = await fetch(`${API_BASE}/scan/${scanId}`);
      const scan = await res.json();
      setActiveScan(scan);
    } catch (_) { }
  }, []);

  const fetchAlerts = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/alerts/history`);
      const data = await res.json();
      setAlertHistory(data);
      setUnreadAlerts(data.filter(a => !a.read).length);
    } catch (_) { }
  }, []);

  // Apply theme to document
  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("theme", theme);
  }, [theme]);

  useEffect(() => { fetchScans(); fetchAlerts(); }, [fetchScans, fetchAlerts]);

  useEffect(() => {
    if (activeScan && activeScan.id) fetchActiveScanDetails(activeScan.id);
  }, [activeScan?.id]);

  useEffect(() => {
    const interval = setInterval(() => {
      fetchScans();
      fetchAlerts();
      if (activeScan && activeScan.id && activeScan.status === "running") {
        fetchActiveScanDetails(activeScan.id);
      }
    }, 5000);
    return () => clearInterval(interval);
  }, [fetchScans, fetchAlerts, activeScan?.id, activeScan?.status, fetchActiveScanDetails]);

  // Keyboard shortcuts
  useEffect(() => {
    const handler = (e) => {
      if (e.key === "k" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); setSearchOpen(true); }
      if (e.key === "?" && !e.ctrlKey) setShortcutsOpen(true);
      if (e.key === "Escape") { setSearchOpen(false); setShortcutsOpen(false); }
      if (e.key === "n" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); setView("dashboard"); setTimeout(() => domainInputRef.current?.focus(), 100); }
      if (e.key === "h" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); setView("history"); }
      if (e.key === "d" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); setView("dashboard"); }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  const openScan = useCallback(async (scanId) => {
    try {
      const res = await fetch(`${API_BASE}/scan/${scanId}`);
      const scan = await res.json();
      setActiveScan(scan);
      setScanLog([]);
      setActiveTab("overview");
      setView("scan");

      // WebSocket for live progress
      if (wsRef.current) wsRef.current.close();
      const ws = new WebSocket(`${WS_BASE}?scanId=${scanId}`);
      ws.onmessage = (e) => {
        const msg = JSON.parse(e.data);
        // Handle alert broadcasts
        if (msg.event === "alert_fired") {
          fetchAlerts();
          const a = msg.alert;
          const emoji = a.riskScore >= 70 ? "🔴" : "🟠";
          showToast(`${emoji} ${a.ruleName}: ${a.domain}`, "warning", 7000);
          // Browser notification
          if (Notification.permission === "granted") {
            new Notification(`⚠ ReconScan Alert: ${a.ruleName}`, { body: `${a.domain} — ${a.triggerDetail}`, icon: "/favicon.ico" });
          }
          return;
        }
        setScanLog(prev => [...prev, { time: new Date().toLocaleTimeString(), ...msg }]);
        if (msg.event === "scan_complete") {
          fetchScans();
          fetchActiveScanDetails(scanId);
          showToast(`✅ Scan complete: ${msg.domain || ""}`, "success");
        }
        if (msg.event === "module_complete" || msg.event === "module_start") {
          fetchScans();
          fetchActiveScanDetails(scanId);
          if (msg.event === "module_complete") showToast(`Module done: ${msg.label || ""}`, "info", 3000);
        }
        if (msg.event === "module_error") showToast(`❌ Error in ${msg.label || "module"}: ${msg.error || ""}`, "error");
      };
      wsRef.current = ws;
    } catch (_) { }
  }, [fetchScans, fetchActiveScanDetails, fetchAlerts]);

  return (
    <div className="app">
      <ToastContainer />
      {searchOpen && <SearchModal scans={scans} onClose={() => setSearchOpen(false)} onSelectScan={(id) => { openScan(id); setSearchOpen(false); }} />}
      {shortcutsOpen && <ShortcutsModal onClose={() => setShortcutsOpen(false)} />}
      <Sidebar view={view} setView={setView} scans={scans} onSelectScan={openScan}
        theme={theme} toggleTheme={() => setTheme(t => t === "dark" ? "light" : "dark")}
        unreadAlerts={unreadAlerts} onSearch={() => setSearchOpen(true)}
        compareIds={compareIds} onOpenCompare={() => setView("compare")}
        setShortcutsOpen={setShortcutsOpen} />
      <main className="main-content">
        {view === "dashboard" && (
          <DashboardView scans={scans} domainInputRef={domainInputRef} onStartScan={(scan) => { setScans(p => [scan, ...p]); openScan(scan.scanId || scan.id); }} onSelectScan={openScan} />
        )}
        {view === "scan" && activeScan && (
          <ScanView scan={activeScan} activeTab={activeTab} setActiveTab={setActiveTab} scanLog={scanLog} />
        )}
        {view === "history" && (<HistoryView scans={scans} onSelectScan={openScan}
          compareIds={compareIds} setCompareIds={setCompareIds}
          onCompare={() => setView("compare")} />)}
        {view === "alerts" && (<AlertsView alertHistory={alertHistory} onMarkRead={async (id) => {
          await fetch(`${API_BASE}/alerts/${id}/read`, { method: "PATCH" }); fetchAlerts();
        }} onMarkAllRead={async () => {
          await fetch(`${API_BASE}/alerts/read-all`, { method: "POST" }); fetchAlerts();
        }} />)}
        {view === "alertSettings" && (<AlertSettingsView />)}
        {view === "compare" && compareIds.length === 2 && (
          <CompareView scanAId={compareIds[0]} scanBId={compareIds[1]}
            onClose={() => { setView("history"); setCompareIds([]); }} />
        )}
      </main>
    </div>
  );
}

// ── Sidebar ───────────────────────────────────────────────────────────────────
function Sidebar({ view, setView, scans, onSelectScan, theme, toggleTheme, unreadAlerts, onSearch, compareIds, onOpenCompare, setShortcutsOpen }) {
  const running = scans.filter(s => s.status === "running");
  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <span className="brand-icon">⬡</span>
        <span className="brand-name">ReconScan</span>
      </div>
      <nav className="sidebar-nav">
        <button className={`nav-item ${view === "dashboard" ? "active" : ""}`} onClick={() => setView("dashboard")}>
          <span className="nav-icon">◈</span> Dashboard
        </button>
        <button className={`nav-item ${view === "history" ? "active" : ""}`} onClick={() => setView("history")}>
          <span className="nav-icon">◷</span> Scan History
        </button>
        {compareIds?.length === 2 && (
          <button className={`nav-item compare-nav-item ${view === "compare" ? "active" : ""}`} onClick={onOpenCompare}>
            <span className="nav-icon">⚖</span> Compare Scans
            <span className="alert-badge" style={{ background: "#7c3aed" }}>2</span>
          </button>
        )}
        <button className={`nav-item ${view === "alerts" ? "active" : ""}`} onClick={() => setView("alerts")}>
          <span className="nav-icon">🚨</span> Alerts
          {unreadAlerts > 0 && <span className="alert-badge">{unreadAlerts}</span>}
        </button>
        <button className={`nav-item ${view === "alertSettings" ? "active" : ""}`} onClick={() => setView("alertSettings")}>
          <span className="nav-icon">⚙</span> Alert Settings
        </button>
        <button className="nav-item" onClick={onSearch}>
          <span className="nav-icon">🔍</span> Search <kbd>Ctrl+K</kbd>
        </button>
      </nav>

      {running.length > 0 && (
        <div className="sidebar-section">
          <div className="section-label">Active Scans</div>
          {running.map(s => (
            <button key={s.id} className="scan-item running" onClick={() => onSelectScan(s.id)}>
              <StatusDot status="running" />
              <span className="scan-domain">{s.domain}</span>
              <span className="scan-progress">{s.progress}%</span>
            </button>
          ))}
        </div>
      )}
      <div className="sidebar-section">
        <div className="section-label">Recent Scans</div>
        {scans.filter(s => s.status !== "running").slice(0, 5).map(s => (
          <button key={s.id} className="scan-item" onClick={() => onSelectScan(s.id)}>
            <StatusDot status={s.status} />
            <span className="scan-domain">{s.domain}</span>
            {s.riskScore && <RiskGrade grade={s.riskScore.grade} small />}
          </button>
        ))}
      </div>
      <div className="sidebar-footer">
        <button className="theme-toggle" onClick={toggleTheme} title="Toggle theme">
          {theme === "dark" ? "☀ Light" : "🌙 Dark"}
        </button>
        <button className="shortcuts-hint" onClick={() => setShortcutsOpen(true)} title="Press ? for shortcuts">⌨ ?</button>
      </div>
    </aside>
  );
}

// ── Dashboard ─────────────────────────────────────────────────────────────────
function DashboardView({ scans, onStartScan, onSelectScan, domainInputRef }) {
  const [domain, setDomain] = useState("");
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState("");

  const handleScan = async () => {
    // Strip protocol, port, path, query string, fragment — accept any URL form
    let raw = domain.trim();
    if (/^https?:\/\//i.test(raw)) {
      try { raw = new URL(raw).hostname; } catch (_) { raw = raw.replace(/^https?:\/\//i, ""); }
    }
    // Also strip port (:8080), paths (/...), query (?...), fragment (#...)
    const d = raw.replace(/[/:?#].*$/, "").toLowerCase().trim();
    if (!d) return;
    setScanning(true); setError("");
    try {
      const res = await fetch(`${API_BASE}/scan/start`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: d }),
      });
      const data = await res.json();
      if (!res.ok) { setError(data.error || "Failed to start scan"); return; }
      onStartScan({ ...data, id: data.scanId, domain: d, status: "running", progress: 0 });
      setDomain("");
    } catch (e) {
      setError("Could not connect to API. Is the backend running?");
    } finally {
      setScanning(false);
    }
  };

  const totalScans = scans.length;
  const criticalScans = scans.filter(s => s.riskScore?.grade === "F" || s.riskScore?.grade === "E").length;
  const completedScans = scans.filter(s => s.status === "complete").length;

  return (
    <div className="view-content">
      <div className="page-header">
        <h1>Security Assessment Platform</h1>
        <p className="page-sub">Agentless external reconnaissance, attack surface analysis & active vulnerability scanning</p>
      </div>

      {/* New Scan Box */}
      <div className="scan-box">
        <div className="scan-box-inner">
          <label className="scan-label">Target Domain</label>
          <div className="scan-input-row">
            <input
              ref={domainInputRef}
              className="scan-input"
              value={domain}
              onChange={e => setDomain(e.target.value)}
              onKeyDown={e => e.key === "Enter" && handleScan()}
              placeholder="e.g. example.com"
              disabled={scanning}
            />
            <button className="scan-btn" onClick={handleScan} disabled={scanning || !domain.trim()}>
              {scanning ? <span className="spinner" /> : null}
              {scanning ? "Starting..." : "Start Scan"}
            </button>
          </div>
          {error && <div className="scan-error">{error}</div>}
          <div className="scan-hint">
            Modules: 🌐 WHOIS &amp; IP · Asset Discovery (subdomains) · 🔒 SSL/TLS (all subdomains) · DNS &amp; Email · Port Scan · Service Fingerprint · Web Tech · Vuln Assessment · ⚔ Active Web Attacks (XSS / SQLi / CMDi / LFI)
          </div>
        </div>
      </div>

      {/* Stats */}
      <div className="stats-row">
        <StatCard label="Total Scans" value={totalScans} />
        <StatCard label="Completed" value={completedScans} />
        <StatCard label="High Risk" value={criticalScans} accent="danger" />
        <StatCard label="Running" value={scans.filter(s => s.status === "running").length} accent="info" />
      </div>

      {/* Portfolio Overview — shown when ≥1 completed scan exists */}
      {(() => {
        const done = scans.filter(s => s.status === "complete" && s.riskScore);
        if (done.length === 0) return null;
        const avgRisk = Math.round(done.reduce((s, x) => s + x.riskScore.score, 0) / done.length);
        const mostAtRisk = [...done].sort((a, b) => b.riskScore.score - a.riskScore.score)[0];
        const totalC = done.reduce((s, x) => s + (x.riskScore.breakdown?.critical || 0), 0);
        const totalH = done.reduce((s, x) => s + (x.riskScore.breakdown?.high || 0), 0);
        return (
          <div className="portfolio-grid">
            <div className="card portfolio-card">
              <div className="card-header">📊 Portfolio Avg Risk</div>
              <div className="portfolio-body">
                <div className="portfolio-score" style={{ color: avgRisk > 60 ? "#e11d48" : avgRisk > 35 ? "#d97706" : "#22c55e" }}>{avgRisk}</div>
                <div>
                  <div style={{ fontSize: "12px", color: "var(--text-muted)" }}>{done.length} completed scan{done.length !== 1 ? "s" : ""}</div>
                  <div style={{ fontSize: "13px", marginTop: "4px" }}>
                    {totalC > 0 && <span className="fc critical" style={{ marginRight: 6 }}>{totalC}C</span>}
                    {totalH > 0 && <span className="fc high">{totalH}H</span>}
                    <span style={{ fontSize: "11px", color: "var(--text-muted)", marginLeft: 6 }}>total</span>
                  </div>
                </div>
              </div>
            </div>
            <div className="card portfolio-card" style={{ cursor: "pointer" }} onClick={() => onSelectScan(mostAtRisk.id)}>
              <div className="card-header" style={{ color: "#f87171" }}>🎯 Most At-Risk Target</div>
              <div className="portfolio-body">
                <RiskGrade grade={mostAtRisk.riskScore.grade} score={mostAtRisk.riskScore.score} />
                <div>
                  <div style={{ fontFamily: "monospace", color: "#60a5fa", fontSize: "13px", fontWeight: 600 }}>{mostAtRisk.domain}</div>
                  <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "4px" }}>{mostAtRisk.riskScore.label} — click to view</div>
                </div>
              </div>
            </div>
          </div>
        );
      })()}

      {/* Risk Trend Chart */}
      {(() => {
        const done = scans.filter(s => s.status === "complete" && s.riskScore);
        if (done.length < 2) return null;
        const trendData = done.slice(0, 10).reverse()
          .map((s, i) => ({ name: s.domain.slice(0, 12), score: s.riskScore.score, grade: s.riskScore.grade, i }));
        return (
          <div className="card">
            <div className="card-header">📊 Risk Score Trend (last {trendData.length} scans)</div>
            <div style={{ padding: "16px 8px" }}>
              <ResponsiveContainer width="100%" height={140}>
                <LineChart data={trendData} margin={{ top: 4, right: 20, left: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e2a40" />
                  <XAxis dataKey="name" tick={{ fill: "#5a6a80", fontSize: 10 }} />
                  <YAxis domain={[0, 100]} tick={{ fill: "#5a6a80", fontSize: 10 }} />
                  <Tooltip
                    contentStyle={{ background: "#0d1220", border: "1px solid #1e2a40", borderRadius: 6, fontSize: 12 }}
                    formatter={(v, _, p) => [`${v} (${p.payload.grade})`, "Risk Score"]}
                  />
                  <Line type="monotone" dataKey="score" stroke="#3b82f6" strokeWidth={2} dot={{ fill: "#3b82f6", r: 4 }} activeDot={{ r: 6 }} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        );
      })()}

      {/* Recent scans table */}
      {scans.length > 0 && (
        <div className="card">
          <div className="card-header">Recent Scans</div>
          <table className="data-table">
            <thead>
              <tr>
                <th>Domain</th>
                <th>Status</th>
                <th>Risk</th>
                <th>Findings</th>
                <th>Started</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {scans.slice(0, 10).map(s => (
                <tr key={s.id} className="table-row" onClick={() => onSelectScan(s.id)}>
                  <td className="domain-cell">{s.domain}</td>
                  <td>
                    <span className={`status-pill ${s.status}`}>
                      <StatusDot status={s.status} />
                      {s.status === "running" ? `${s.progress}%` : s.status}
                    </span>
                  </td>
                  <td>{s.riskScore ? <RiskGrade grade={s.riskScore.grade} score={s.riskScore.score} /> : "—"}</td>
                  <td>{s.riskScore ? (
                    <span className="findings-count">
                      {s.riskScore.breakdown?.critical > 0 && <span className="fc critical">{s.riskScore.breakdown.critical}C</span>}
                      {s.riskScore.breakdown?.high > 0 && <span className="fc high">{s.riskScore.breakdown.high}H</span>}
                      {s.riskScore.breakdown?.medium > 0 && <span className="fc medium">{s.riskScore.breakdown.medium}M</span>}
                    </span>
                  ) : "—"}</td>
                  <td className="time-cell">{new Date(s.startedAt).toLocaleString()}</td>
                  <td className="arrow-cell">›</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ── Scan View ─────────────────────────────────────────────────────────────────
function ScanView({ scan, activeTab, setActiveTab, scanLog }) {
  const sslData = scan.modules?.sslScan?.data;
  const sslBadge = sslData?.summary?.expired > 0
    ? ` 🔴${sslData.summary.expired}`
    : sslData?.summary?.expiring > 0
      ? ` 🟡${sslData.summary.expiring}`
      : "";

  const nucleiData = scan.modules?.nucleiChecks?.data;
  const nucleiBadge = nucleiData?.summary?.totalIssues > 0 ? ` (${nucleiData.summary.totalIssues})` : "";

  const jsData = scan.modules?.jsSecretScanner?.data;
  const jsBadge = jsData?.summary?.totalIssues > 0 ? ` 🔑${jsData.summary.totalIssues}` : "";

  const takeoverData = scan.modules?.subdomainTakeover?.data;
  const takeoverBadge = takeoverData?.summary?.vulnerable > 0 ? ` ⚠️${takeoverData.summary.vulnerable}` : "";

  const wafData = scan.modules?.wafDetector?.data;
  const wafBadge = wafData?.isProtected ? ` 🛡️` : "";

  const vulnData = scan.modules?.vulnAssessment?.data;
  // Handle multi-target vuln data — pick the first target result for badge
  const vulnSummary = vulnData?.multiTarget
    ? (vulnData.targetResults?.[0]?.summary || {})
    : (vulnData?.summary || {});
  const vulnBadge = vulnSummary.fail > 0 ? ` ❌${vulnSummary.fail}` : vulnSummary.pass > 0 ? " ✓" : "";

  const cveData = scan.modules?.cveEnrichment?.data;
  const cveBadge = cveData?.summary?.total > 0 ? ` 🔴${cveData.summary.total}` : "";

  const retireData = scan.modules?.retireJsChecker?.data;
  const retireBadge = retireData?.summary?.total > 0 ? ` ⚠️${retireData.summary.total}` : "";

  const apiData = scan.modules?.apiDiscovery?.data;
  const apiBadge = apiData?.summary?.total > 0 ? ` 🔗${apiData.summary.total}` :
    apiData?.jsEndpoints?.length > 0 ? ` 🔗${apiData.jsEndpoints.length}` : "";

  const tabs = [
    { id: "overview", label: "Overview" },
    { id: "whois", label: "🌐 WHOIS & IP" },
    { id: "assets", label: "Assets" },
    { id: "ssl", label: `🔒 SSL/TLS${sslBadge}` },
    { id: "dns", label: "DNS & Email" },
    { id: "ports", label: "Ports" },
    { id: "services", label: "Services" },
    { id: "webtech", label: "Web Tech" },
    { id: "waf", label: `WAF/CDN${wafBadge}` },
    { id: "vuln", label: `🛡 Vuln Assess${vulnBadge}` },
    { id: "nuclei", label: `🎯 Nuclei${nucleiBadge}` },
    { id: "cve", label: `📋 CVE Lookup${cveBadge}` },
    { id: "retirejs", label: `📦 Retire.js${retireBadge}` },
    { id: "api", label: `🔗 API Discover${apiBadge}` },
    { id: "secrets", label: `JS Secrets${jsBadge}` },
    { id: "takeover", label: `Takeover${takeoverBadge}` },
    { id: "webattacks", label: `⚔ Web Attacks ${scan.modules?.wapitiscan?.data?.findings?.length ? `(${scan.modules.wapitiscan.data.findings.length})` : ""}` },
    { id: "cms", label: `🏛 CMS ${scan.modules?.cmsVulnScan?.data?.findings?.length ? `(${scan.modules.cmsVulnScan.data.findings.length})` : ""}` },
    { id: "findings", label: `Findings ${scan.findings?.length ? `(${scan.findings.length})` : ""}` },
    { id: "log", label: "Live Log" },
  ];

  return (
    <div className="view-content">
      <div className="page-header">
        <div className="scan-header-top">
          <div>
            <h1>{scan.domain}</h1>
            <div className="scan-meta">
              <StatusDot status={scan.status} />
              <span className={`status-text ${scan.status}`}>{scan.status}</span>
              {scan.status === "running" && (
                <div className="progress-bar-inline">
                  <div className="progress-fill" style={{ width: `${scan.progress}%` }} />
                </div>
              )}
              <span className="scan-time">{new Date(scan.startedAt).toLocaleString()}</span>
            </div>
          </div>
          {scan.riskScore && <RiskScoreCard riskScore={scan.riskScore} />}
          {scan.status === "complete" && (
            <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", justifyContent: "flex-end" }}>
              <a href={`${API_BASE}/report/${scan.id}/pdf`} download className="export-btn" style={{ background: "rgba(225, 29, 72, 0.15)", color: "#f43f5e", borderColor: "rgba(225, 29, 72, 0.3)" }}>📄 PDF
              </a>
              <a href={`${API_BASE}/report/${scan.id}/markdown`} download className="export-btn">📝 MD
              </a>
              <a href={`${API_BASE}/report/${scan.id}/download`} download className="export-btn">💾 JSON
              </a>
              <button className="export-btn" onClick={() => copyText(JSON.stringify(scan.findings, null, 2))}>📋 Copy Findings
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Module pipeline status */}
      <ModulePipeline modules={scan.modules} />

      {/* Tabs */}
      <div className="tabs">
        {tabs.map(t => (
          <button key={t.id} className={`tab ${activeTab === t.id ? "active" : ""}`} onClick={() => setActiveTab(t.id)}>
            {t.label}
          </button>
        ))}
      </div>

      <div className="tab-content">
        {activeTab === "overview" && <OverviewTab scan={scan} />}
        {activeTab === "whois" && <WhoisTab data={scan.modules?.whoisLookup?.data} status={scan.modules?.whoisLookup?.status} />}
        {activeTab === "assets" && <AssetsTab data={scan.modules?.assetDiscovery?.data} />}
        {activeTab === "ssl" && <SSLScanTab data={scan.modules?.sslScan?.data} status={scan.modules?.sslScan?.status} />}
        {activeTab === "dns" && <DNSTab data={scan.modules?.dnsAssessment?.data} />}
        {activeTab === "ports" && <PortsTab data={scan.modules?.portScan?.data} />}
        {activeTab === "services" && <ServicesTab data={scan.modules?.serviceFingerprint?.data} />}
        {activeTab === "webtech" && <WebTechTab data={scan.modules?.webTechFingerprint?.data} />}
        {activeTab === "waf" && <WAFDetectorTab data={scan.modules?.wafDetector?.data} status={scan.modules?.wafDetector?.status} />}
        {activeTab === "vuln" && <VulnAssessmentTab data={scan.modules?.vulnAssessment?.data} status={scan.modules?.vulnAssessment?.status} />}
        {activeTab === "nuclei" && <NucleiChecksTab data={scan.modules?.nucleiChecks?.data} status={scan.modules?.nucleiChecks?.status} />}
        {activeTab === "cve" && <CVEEnrichmentTab data={scan.modules?.cveEnrichment?.data} status={scan.modules?.cveEnrichment?.status} />}
        {activeTab === "retirejs" && <RetireJsTab data={scan.modules?.retireJsChecker?.data} status={scan.modules?.retireJsChecker?.status} />}
        {activeTab === "api" && <APIDiscoveryTab data={scan.modules?.apiDiscovery?.data} status={scan.modules?.apiDiscovery?.status} />}
        {activeTab === "secrets" && <JSSecretTab data={scan.modules?.jsSecretScanner?.data} status={scan.modules?.jsSecretScanner?.status} />}
        {activeTab === "takeover" && <TakeoverTab data={scan.modules?.subdomainTakeover?.data} status={scan.modules?.subdomainTakeover?.status} />}
        {activeTab === "webattacks" && <WebAttacksTab data={scan.modules?.wapitiscan?.data} status={scan.modules?.wapitiscan?.status} />}
        {activeTab === "cms" && <CMSScanTab data={scan.modules?.cmsVulnScan?.data} status={scan.modules?.cmsVulnScan?.status} />}
        {activeTab === "findings" && <FindingsTab findings={scan.findings} />}
        {activeTab === "log" && <LiveLogTab logs={scanLog} />}
      </div>
    </div>
  );
}

// ── Module Pipeline ───────────────────────────────────────────────────────────
function ModulePipeline({ modules }) {
  const MODULES = [
    { key: "whoisLookup", label: "WHOIS & IP" },
    { key: "assetDiscovery", label: "Assets" },
    { key: "sslScan", label: "SSL/TLS" },
    { key: "dnsAssessment", label: "DNS & Email" },
    { key: "portScan", label: "Port Scan" },
    { key: "serviceFingerprint", label: "Services" },
    { key: "webTechFingerprint", label: "Web Tech" },
    { key: "wafDetector", label: "WAF/CDN" },
    { key: "vulnAssessment", label: "Vuln Assess" },
    { key: "nucleiChecks", label: "Nuclei" },
    { key: "cveEnrichment", label: "CVE Lookup" },
    { key: "retireJsChecker", label: "Retire.js" },
    { key: "apiDiscovery", label: "API Discover" },
    { key: "jsSecretScanner", label: "JS Secrets" },
    { key: "subdomainTakeover", label: "Takeover" },
    { key: "wapitiscan", label: "Web Attacks" },
    { key: "cmsVulnScan", label: "CMS Scan" },
  ];
  return (
    <div className="module-pipeline">
      {MODULES.map((m, i) => {
        const mod = modules?.[m.key];
        const status = mod?.status || "pending";
        return (
          <div key={m.key} className="pipeline-step">
            <div className={`pipeline-node ${status}`}>
              {status === "running" ? <span className="spinner-sm" /> : status === "complete" ? "✓" : status === "error" ? "✗" : i + 1}
            </div>
            <div className="pipeline-label">{m.label}</div>
            {i < MODULES.length - 1 && <div className={`pipeline-connector ${status === "complete" ? "done" : ""}`} />}
          </div>
        );
      })}
    </div>
  );
}

// ── Target Selector ───────────────────────────────────────────────────────────
function TargetSelector({ rawData, selectedTarget, setSelectedTarget }) {
  if (!rawData?.multiTarget || !rawData?.targetResults || rawData.targetResults.length <= 1) return null;
  return (
    <div className="target-selector">
      <label>Target Domain:</label>
      <select value={selectedTarget || ""} onChange={(e) => setSelectedTarget(e.target.value)}>
        {rawData.targetResults.map(tr => (
          <option key={tr.domain} value={tr.domain}>{tr.domain}</option>
        ))}
      </select>
    </div>
  );
}

// ── Overview Tab ──────────────────────────────────────────────────────────────
function OverviewTab({ scan }) {
  const { summary, findings, riskScore } = scan;
  if (!summary && !findings?.length) {
    return <div className="empty-state">Scan in progress — results will appear here.</div>;
  }

  const topFindings = (findings || [])
    .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])
    .slice(0, 5);

  const radarData = riskScore ? [
    { subject: "DNS", A: riskScore.breakdown?.medium || 0 },
    { subject: "Ports", A: riskScore.breakdown?.high || 0 },
    { subject: "Services", A: riskScore.breakdown?.low || 0 },
    { subject: "Web", A: riskScore.breakdown?.critical || 0 },
    { subject: "Assets", A: Math.min(summary?.totalAssets / 10 || 0, 10) },
  ] : [];

  const barData = riskScore?.breakdown ? [
    { name: "Critical", count: riskScore.breakdown.critical, fill: "#e11d48" },
    { name: "High", count: riskScore.breakdown.high, fill: "#ea580c" },
    { name: "Medium", count: riskScore.breakdown.medium, fill: "#d97706" },
    { name: "Low", count: riskScore.breakdown.low, fill: "#16a34a" },
  ] : [];

  return (
    <div className="overview-grid">
      {summary && (
        <div className="card summary-stats">
          <div className="card-header">Scan Summary</div>
          <div className="summary-grid">
            <SummaryItem label="Subdomains" value={summary.totalAssets} />
            <SummaryItem label="Live Hosts" value={summary.liveHosts} />
            <SummaryItem label="Open Ports" value={summary.openPorts} />
            <SummaryItem label="Services" value={summary.exposedServices} />
            <SummaryItem label="Technologies" value={summary.technologies} />
            <SummaryItem label="DNS Issues" value={summary.dnsIssues} accent={summary.dnsIssues > 0} />
            <SummaryItem label="SSL Scanned" value={summary.sslScanned || 0} />
            <SummaryItem label="SSL Expired" value={summary.sslExpired || 0} accent={summary.sslExpired > 0} />
            <SummaryItem label="SSL Expiring" value={summary.sslExpiring || 0} accent={summary.sslExpiring > 0} />
            <SummaryItem label="Active Probes" value={summary.activeProbes || 0} />
            <SummaryItem label="Attack Findings" value={summary.activeAttackFindings || 0} accent={summary.activeAttackFindings > 0} />
          </div>
        </div>
      )}

      {barData.length > 0 && (
        <div className="card">
          <div className="card-header">Finding Distribution</div>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={barData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <XAxis dataKey="name" tick={{ fontSize: 12 }} />
              <YAxis tick={{ fontSize: 12 }} />
              <Tooltip />
              <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                {barData.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {topFindings.length > 0 && (
        <div className="card findings-preview">
          <div className="card-header">Top Findings</div>
          {topFindings.map(f => (
            <div key={f.id} className="finding-row">
              <SeverityBadge severity={f.severity} />
              <div className="finding-text">
                <div className="finding-title">{f.title}</div>
                <div className="finding-module">{f.module}</div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Assets Tab ────────────────────────────────────────────────────────────────
function AssetsTab({ data }) {
  if (!data) return <div className="empty-state">Asset discovery module pending.</div>;
  return (
    <div className="tab-sections">
      <div className="card">
        <div className="card-header">Subdomains ({data.subdomains?.length || 0})</div>
        <div className="scrollable-list">
          {(data.subdomains || []).map(s => (
            <div key={s} className="list-item">
              <span className="list-dot" />
              {s}
            </div>
          ))}
        </div>
      </div>
      <div className="card">
        <div className="card-header">Live Hosts ({data.liveHosts?.length || 0})</div>
        <div className="scrollable-list">
          {(data.liveHosts || []).map((h, i) => (
            <div key={i} className="list-item host-item">
              <span className={`http-status s${Math.floor((h.status || 200) / 100)}xx`}>{h.status || "200"}</span>
              <a href={h.url} target="_blank" rel="noreferrer">{h.url}</a>
            </div>
          ))}
        </div>
      </div>
      {data.wafDetected?.length > 0 && (
        <div className="card">
          <div className="card-header">WAF / CDN Detected</div>
          {data.wafDetected.map((w, i) => (
            <div key={i} className="list-item"><span className="tag waf">{w.waf}</span> {w.host}</div>
          ))}
          {data.cdnProviders?.map((c, i) => (
            <div key={i} className="list-item"><span className="tag cdn">{c.provider}</span> {c.host}</div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── DNS Tab ───────────────────────────────────────────────────────────────────
function DNSTab({ data: rawData }) {
  const isMulti = rawData?.multiTarget;
  const [selectedTarget, setSelectedTarget] = useState(isMulti ? rawData.targetResults[0]?.domain : null);
  const data = isMulti ? (rawData.targetResults.find(t => t.domain === selectedTarget) || rawData.targetResults[0]) : rawData;

  if (!data) return <div className="empty-state">DNS assessment pending.</div>;
  const checks = [
    { label: "SPF", pass: data.spf?.present, detail: data.spf?.record || "Not configured" },
    { label: "DMARC", pass: data.dmarc?.present, detail: data.dmarc?.policy ? `p=${data.dmarc.policy}` : "Not configured" },
    { label: "DKIM", pass: data.dkim?.configured, detail: data.dkim?.selectors?.map(s => s.selector).join(", ") || "Not found" },
    { label: "DNSSEC", pass: data.dnssec?.enabled, detail: data.dnssec?.enabled ? "Enabled" : "Not enabled" },
    { label: "Zone Transfer", pass: !data.zoneTransfer?.vulnerable, detail: data.zoneTransfer?.vulnerable ? "VULNERABLE" : "Protected" },
  ];

  return (
    <div className="tab-sections">
      <TargetSelector rawData={rawData} selectedTarget={selectedTarget} setSelectedTarget={setSelectedTarget} />
      <div className="card">
        <div className="card-header">Email Security Checks</div>
        <div className="dns-checks">
          {checks.map(c => (
            <div key={c.label} className="dns-check">
              <span className={`check-icon ${c.pass ? "pass" : "fail"}`}>{c.pass ? "✓" : "✗"}</span>
              <span className="check-label">{c.label}</span>
              <span className="check-detail">{c.detail}</span>
            </div>
          ))}
        </div>
      </div>
      <div className="card">
        <div className="card-header">DNS Records</div>
        {["a", "aaaa", "mx", "txt"].map(type => data.records?.[type]?.length > 0 && (
          <div key={type} className="dns-record-group">
            <div className="record-type">{type.toUpperCase()}</div>
            {data.records[type].map((r, i) => (
              <div key={i} className="record-value">
                {typeof r === "object" ? `${r.priority} ${r.exchange}` : r}
              </div>
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Ports Tab ─────────────────────────────────────────────────────────────────
function PortsTab({ data: rawData }) {
  const isMulti = rawData?.multiTarget;
  const [selectedTarget, setSelectedTarget] = useState(isMulti ? rawData.targetResults[0]?.domain : null);
  const data = isMulti ? (rawData.targetResults.find(t => t.domain === selectedTarget) || rawData.targetResults[0]) : rawData;

  if (!data) return <div className="empty-state">Port scan pending.</div>;
  const dangerous = data.exposedDangerousPorts || [];
  const other = (data.openPorts || []).filter(p => !dangerous.find(d => d.port === p.port));

  return (
    <div className="tab-sections">
      <TargetSelector rawData={rawData} selectedTarget={selectedTarget} setSelectedTarget={setSelectedTarget} />
      {dangerous.length > 0 && (
        <div className="card">
          <div className="card-header danger">⚠ Dangerous Exposures ({dangerous.length})</div>
          <table className="data-table">
            <thead><tr><th>Port</th><th>Service</th><th>Risk</th><th>Severity</th></tr></thead>
            <tbody>
              {dangerous.map(p => (
                <tr key={p.port}>
                  <td><code>{p.port}/{p.protocol}</code></td>
                  <td>{p.service}</td>
                  <td className="reason-cell">{p.reason}</td>
                  <td><SeverityBadge severity={p.severity} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className="card">
        <div className="card-header">All Open Ports ({data.openPorts?.length || 0})</div>
        <table className="data-table">
          <thead><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Banner</th></tr></thead>
          <tbody>
            {(data.openPorts || []).map(p => (
              <tr key={p.port}>
                <td><code>{p.port}</code></td>
                <td>{p.protocol}</td>
                <td>{p.service}</td>
                <td className="banner-cell">{p.banner || p.product || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── Services Tab ──────────────────────────────────────────────────────────────
function ServicesTab({ data: rawData }) {
  const isMulti = rawData?.multiTarget;
  const [selectedTarget, setSelectedTarget] = useState(isMulti ? rawData.targetResults[0]?.domain : null);
  const data = isMulti ? (rawData.targetResults.find(t => t.domain === selectedTarget) || rawData.targetResults[0]) : rawData;

  if (!data) return <div className="empty-state">Service fingerprinting pending.</div>;
  return (
    <div className="tab-sections">
      <TargetSelector rawData={rawData} selectedTarget={selectedTarget} setSelectedTarget={setSelectedTarget} />
      <div className="card">
        <div className="card-header">Identified Services</div>
        <table className="data-table">
          <thead><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th><th>Status</th></tr></thead>
          <tbody>
            {(data.softwareVersions || data.services || []).map((s, i) => (
              <tr key={i}>
                <td><code>{s.port}</code></td>
                <td>{s.service || "—"}</td>
                <td>{s.product || s.serverHeader || "—"}</td>
                <td>{s.version || "—"}</td>
                <td>{s.vulnerable ? <SeverityBadge severity={s.vulnSeverity || "high"} /> : <span className="ok-badge">OK</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {data.services?.find(s => s.headers) && (
        <div className="card">
          <div className="card-header">HTTP Security Headers</div>
          {(() => {
            const svc = data.services.find(s => s.headers);
            const hdrs = svc?.headers || {};
            return Object.entries(hdrs).map(([k, v]) => (
              <div key={k} className="header-row">
                <span className={`header-status ${v ? "present" : "missing"}`}>{v ? "✓" : "✗"}</span>
                <span className="header-name">{k}</span>
                <span className="header-value">{v || "Not set"}</span>
              </div>
            ));
          })()}
        </div>
      )}
    </div>
  );
}

// ── Web Tech Tab ──────────────────────────────────────────────────────────────
function WebTechTab({ data: rawData }) {
  const isMulti = rawData?.multiTarget;
  const [selectedTarget, setSelectedTarget] = useState(isMulti ? rawData.targetResults[0]?.domain : null);
  const data = isMulti ? (rawData.targetResults.find(t => t.domain === selectedTarget) || rawData.targetResults[0]) : rawData;

  if (!data) return <div className="empty-state">Web technology fingerprinting pending.</div>;

  const byCategory = {};
  (data.technologies || []).forEach(t => {
    if (!byCategory[t.category]) byCategory[t.category] = [];
    byCategory[t.category].push(t);
  });

  return (
    <div className="tab-sections">
      <TargetSelector rawData={rawData} selectedTarget={selectedTarget} setSelectedTarget={setSelectedTarget} />
      <div className="tech-grid">
        {Object.entries(byCategory).map(([cat, techs]) => (
          <div key={cat} className="card tech-category">
            <div className="card-header">{cat}</div>
            {techs.map(t => (
              <div key={t.name} className="tech-item">
                <span className="tech-name">{t.name}</span>
                <span className={`confidence ${t.confidence}`}>{t.confidence}</span>
                {t.evidence && <span className="tech-evidence">{t.evidence.substring(0, 50)}</span>}
              </div>
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}

// ── SSL/TLS Scan Tab ──────────────────────────────────────────────────────────
function SSLScanTab({ data, status }) {
  const fmtDate = (d) => {
    if (!d) return "—";
    try { return new Date(d).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }); }
    catch (_) { return d; }
  };

  if (status === "pending" || !data) {
    return (
      <div className="empty-state">
        <div style={{ fontSize: "2.5rem", marginBottom: "0.75rem" }}>🔒</div>
        <div style={{ fontWeight: 600, marginBottom: "0.5rem" }}>SSL/TLS Certificate Scan Pending</div>
        <div style={{ color: "var(--text-muted)", fontSize: "0.875rem" }}>
          Certificate data for the main domain and all discovered subdomains will appear here.
        </div>
      </div>
    );
  }

  if (status === "running") {
    return (
      <div className="empty-state">
        <span className="spinner" style={{ width: 32, height: 32, marginBottom: "1rem" }} />
        <div style={{ fontWeight: 600 }}>Scanning SSL Certificates...</div>
        <div style={{ color: "var(--text-muted)", fontSize: "0.875rem", marginTop: "0.5rem" }}>
          Checking all discovered subdomains for certificate validity and expiry
        </div>
      </div>
    );
  }

  const { hosts = [], summary = {} } = data;

  const STATUS_CONFIG = {
    valid: { label: "Valid", color: "#22c55e", bg: "rgba(34,197,94,0.12)", icon: "✓" },
    expiring: { label: "Expiring", color: "#f59e0b", bg: "rgba(245,158,11,0.12)", icon: "⚠" },
    expired: { label: "Expired", color: "#e11d48", bg: "rgba(225,29,72,0.12)", icon: "✗" },
    no_ssl: { label: "No SSL", color: "#6b7280", bg: "rgba(107,114,128,0.12)", icon: "—" },
    error: { label: "Error", color: "#6b7280", bg: "rgba(107,114,128,0.12)", icon: "?" },
  };

  return (
    <div className="tab-sections">
      {/* Summary row */}
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-header">🔒 SSL/TLS Certificate Overview</div>
        <div className="summary-grid" style={{ padding: "12px 16px" }}>
          {[
            { label: "Hosts Scanned", value: summary.total || 0, color: null },
            { label: "Valid", value: summary.valid || 0, color: "#22c55e" },
            { label: "Expiring Soon", value: summary.expiring || 0, color: "#f59e0b" },
            { label: "Expired", value: summary.expired || 0, color: "#e11d48" },
            { label: "No SSL", value: summary.noSSL || 0, color: "#6b7280" },
          ].map(item => (
            <div key={item.label} className="summary-item">
              <span className="summary-value" style={item.color ? { color: item.color } : {}}>{item.value}</span>
              <span className="summary-label">{item.label}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Per-host certificate table */}
      <div className="card">
        <div className="card-header">Certificate Details — All Hosts ({hosts.length})</div>
        <div style={{ overflowX: "auto" }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Host</th>
                <th>Status</th>
                <th>Days Left</th>
                <th>Expiry Date</th>
                <th>Issuer</th>
                <th>Protocol</th>
                <th>Subject / CN</th>
              </tr>
            </thead>
            <tbody>
              {hosts.map((h, i) => {
                const cfg = STATUS_CONFIG[h.status] || STATUS_CONFIG.error;
                const daysLeftColor =
                  h.daysLeft === null ? "var(--text-muted)"
                    : h.daysLeft < 0 ? "#e11d48"
                      : h.daysLeft <= 7 ? "#e11d48"
                        : h.daysLeft <= 30 ? "#f59e0b"
                          : "#22c55e";

                return (
                  <tr key={i}>
                    <td>
                      <a href={`https://${h.host}`} target="_blank" rel="noreferrer"
                        style={{ color: "#60a5fa", fontFamily: "monospace", fontSize: 12 }}>
                        {h.host}
                      </a>
                    </td>
                    <td>
                      <span style={{
                        display: "inline-flex", alignItems: "center", gap: 5,
                        padding: "2px 10px", borderRadius: 12, fontSize: 12, fontWeight: 600,
                        background: cfg.bg, color: cfg.color,
                      }}>
                        {cfg.icon} {cfg.label}
                      </span>
                    </td>
                    <td style={{ color: daysLeftColor, fontWeight: 600, fontFamily: "monospace" }}>
                      {h.daysLeft === null ? "—"
                        : h.daysLeft < 0 ? `Expired ${Math.abs(h.daysLeft)}d ago`
                          : `${h.daysLeft}d`}
                    </td>
                    <td style={{ fontSize: 12, color: "var(--text-muted)" }}>{fmtDate(h.validTo)}</td>
                    <td style={{ fontSize: 12 }}>
                      {h.selfSigned
                        ? <span style={{ color: "#f59e0b", fontWeight: 600 }}>⚠ Self-Signed</span>
                        : h.issuer || "—"}
                    </td>
                    <td>
                      {h.protocol ? (
                        <code style={{
                          fontSize: 11,
                          color: (h.protocol === "TLSv1" || h.protocol === "TLSv1.1") ? "#f59e0b" : "#22c55e",
                        }}>
                          {h.protocol}
                        </code>
                      ) : "—"}
                    </td>
                    <td style={{ fontSize: 12, fontFamily: "monospace", color: "var(--text-muted)" }}>
                      {h.subject || h.error || "—"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* SAN list for any host with SANs */}
      {hosts.filter(h => h.san?.length > 0).map(h => (
        <div key={h.host} className="card" style={{ marginTop: 12 }}>
          <div className="card-header">📜 Subject Alternative Names — {h.host} ({h.san.length})</div>
          <div className="scrollable-list">
            {h.san.map((s, i) => (
              <div key={i} className="list-item" style={{ fontFamily: "monospace", fontSize: 12 }}>
                <span className="list-dot" />
                {s}
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

// ── Nuclei Checks Tab ─────────────────────────────────────────────────────────
function NucleiChecksTab({ data: rawData, status }) {
  const isMulti = rawData?.multiTarget;
  const [selectedTarget, setSelectedTarget] = useState(isMulti ? rawData.targetResults[0]?.domain : null);
  const data = isMulti ? (rawData.targetResults.find(t => t.domain === selectedTarget) || rawData.targetResults[0]) : rawData;

  const SEV_COLOR = {
    critical: { bg: "rgba(225,29,72,0.12)", color: "#e11d48", label: "CRITICAL" },
    high: { bg: "rgba(239,68,68,0.12)", color: "#ef4444", label: "HIGH" },
    medium: { bg: "rgba(245,158,11,0.12)", color: "#f59e0b", label: "MEDIUM" },
    low: { bg: "rgba(34,197,94,0.1)", color: "#22c55e", label: "LOW" },
    info: { bg: "rgba(96,165,250,0.1)", color: "#60a5fa", label: "INFO" },
  };

  if (status === "pending" || !data) {
    return (
      <div className="empty-state">
        <div style={{ fontSize: "2.5rem", marginBottom: "0.75rem" }}>🎯</div>
        <div style={{ fontWeight: 600, marginBottom: "0.5rem" }}>Nuclei-style Checks Pending</div>
        <div style={{ color: "var(--text-muted)", fontSize: "0.875rem" }}>
          Template-based security checks (25 panels, 13 CVE probes, misconfigs, API issues) will appear here.
        </div>
      </div>
    );
  }
  if (status === "running") {
    return (
      <div className="empty-state">
        <span className="spinner" style={{ width: 32, height: 32, marginBottom: "1rem" }} />
        <div style={{ fontWeight: 600 }}>Running Nuclei-style Template Checks...</div>
        <div style={{ color: "var(--text-muted)", fontSize: "0.875rem", marginTop: "0.5rem" }}>
          Checking panels, CVE probes, tech misconfigs, API issues
        </div>
      </div>
    );
  }

  const { findings = [], summary = {}, panelsFound = [], cveProbeHits = [] } = data;

  const grouped = findings.reduce((acc, f) => {
    const cat = f.id?.startsWith("NUCLEI-PANEL") ? "Exposed Panels"
      : f.id?.startsWith("NUCLEI-CVE") ? "CVE Probes"
        : f.id?.startsWith("NUCLEI-PHP") || f.id?.startsWith("NUCLEI-EXPRESS") || f.id?.startsWith("NUCLEI-SOURCEMAP") || f.id?.startsWith("NUCLEI-WERKZEUG") || f.id?.startsWith("NUCLEI-DJANGO") || f.id?.startsWith("NUCLEI-ACTUATOR") ? "Tech Misconfigs"
          : "API & Other";
    if (!acc[cat]) acc[cat] = [];
    acc[cat].push(f);
    return acc;
  }, {});

  const catIcons = {
    "Exposed Panels": "🖥️",
    "CVE Probes": "💀",
    "Tech Misconfigs": "⚙️",
    "API & Other": "🔌",
  };

  return (
    <div className="tab-sections">
      <TargetSelector rawData={rawData} selectedTarget={selectedTarget} setSelectedTarget={setSelectedTarget} />
      {/* Summary row */}
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-header">🎯 Nuclei-style Check Results</div>
        <div className="summary-grid" style={{ padding: "12px 16px" }}>
          {[
            { label: "Panels Checked", value: summary.panelsChecked || 0, color: null },
            { label: "Panels Found", value: summary.panelsFound || 0, color: summary.panelsFound > 0 ? "#e11d48" : "#22c55e" },
            { label: "CVE Probes Run", value: summary.cveProbes || 0, color: null },
            { label: "CVE Hits", value: summary.cveHits || 0, color: summary.cveHits > 0 ? "#e11d48" : "#22c55e" },
            { label: "Tech Issues", value: summary.techMisconfigs || 0, color: summary.techMisconfigs > 0 ? "#f59e0b" : null },
            { label: "API Issues", value: summary.apiIssues || 0, color: summary.apiIssues > 0 ? "#f59e0b" : null },
            { label: "Total Issues", value: summary.totalIssues || 0, color: summary.totalIssues > 0 ? "#e11d48" : "#22c55e" },
          ].map(item => (
            <div key={item.label} className="summary-item">
              <span className="summary-value" style={item.color ? { color: item.color } : {}}>{item.value}</span>
              <span className="summary-label">{item.label}</span>
            </div>
          ))}
        </div>
      </div>

      {findings.length === 0 ? (
        <div className="card" style={{ padding: "2rem", textAlign: "center" }}>
          <div style={{ fontSize: "2rem", marginBottom: "0.5rem" }}>✅</div>
          <div style={{ fontWeight: 600, color: "#22c55e" }}>No Issues Found</div>
          <div style={{ color: "var(--text-muted)", fontSize: "0.875rem", marginTop: "0.5rem" }}>
            All {(summary.panelsChecked || 0) + (summary.cveProbes || 0)} checks passed with no findings.
          </div>
        </div>
      ) : (
        Object.entries(grouped).map(([cat, items]) => (
          <div key={cat} className="card" style={{ marginBottom: 14 }}>
            <div className="card-header">{catIcons[cat] || "🔍"} {cat} ({items.length})</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 10, padding: "12px 16px" }}>
              {items.map((f, i) => {
                const sc = SEV_COLOR[f.severity] || SEV_COLOR.info;
                return (
                  <div key={i} style={{
                    background: "rgba(255,255,255,0.03)", border: `1px solid rgba(255,255,255,0.06)`,
                    borderLeft: `3px solid ${sc.color}`, borderRadius: 8, padding: "12px 14px",
                  }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
                      <span style={{ background: sc.bg, color: sc.color, fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 10, letterSpacing: "0.05em" }}>{sc.label}</span>
                      <span style={{ fontWeight: 600, fontSize: "0.9rem" }}>{f.title}</span>
                    </div>
                    <div style={{ color: "var(--text-muted)", fontSize: "0.82rem", lineHeight: 1.5, marginBottom: 6 }}>{f.description}</div>
                    {f.affected && (
                      <div style={{ marginBottom: 6 }}>
                        <a href={f.affected} target="_blank" rel="noreferrer" style={{ color: "#60a5fa", fontFamily: "monospace", fontSize: 11 }}>{f.affected}</a>
                      </div>
                    )}
                    {f.remediation && (
                      <div style={{ background: "rgba(34,197,94,0.08)", borderRadius: 6, padding: "6px 10px", fontSize: "0.8rem", color: "#86efac", borderLeft: "2px solid #22c55e" }}>
                        <span style={{ fontWeight: 600 }}>Fix: </span>{f.remediation}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        ))
      )}
    </div>
  );
}

// ── Findings Tab ──────────────────────────────────────────────────────────────
function FindingsTab({ findings }) {
  const [filter, setFilter] = useState("all");
  const [expanded, setExpanded] = useState(null);

  if (!findings?.length) return <div className="empty-state">No findings yet.</div>;

  const sorted = [...findings].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  const filtered = filter === "all" ? sorted : sorted.filter(f => f.severity === filter);

  return (
    <div>
      <div className="filter-row">
        {["all", "critical", "high", "medium", "low"].map(s => (
          <button key={s} className={`filter-btn ${filter === s ? "active" : ""} ${s}`} onClick={() => setFilter(s)}>
            {s === "all" ? `All (${findings.length})` : `${s} (${findings.filter(f => f.severity === s).length})`}
          </button>
        ))}
      </div>
      <div className="findings-list">
        {filtered.map(f => (
          <div key={f.id} className={`finding-card ${f.severity} ${expanded === f.id ? "expanded" : ""}`}
            onClick={() => setExpanded(expanded === f.id ? null : f.id)}>
            <div className="finding-card-header">
              <SeverityBadge severity={f.severity} />
              <span className="finding-card-title">{f.title}</span>
              <span className="finding-module-tag">{f.module}</span>
              <span className="expand-icon">{expanded === f.id ? "▲" : "▼"}</span>
            </div>
            {expanded === f.id && (
              <div className="finding-card-body">
                <div className="finding-section">
                  <div className="finding-section-label">Description</div>
                  <div>{f.description}</div>
                </div>
                {f.affected && (
                  <div className="finding-section">
                    <div className="finding-section-label">Affected</div>
                    <code>{f.affected}</code>
                  </div>
                )}
                {f.remediation && (
                  <div className="finding-section remediation">
                    <div className="finding-section-label">Remediation</div>
                    <div>{f.remediation}</div>
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

// ── WHOIS & IP Intel Tab ──────────────────────────────────────────────────────
function WhoisTab({ data, status }) {
  if (!data || status === "pending") {
    return (
      <div className="empty-state">
        <div style={{ fontSize: "2.5rem", marginBottom: "0.75rem" }}>🌐</div>
        <div style={{ fontWeight: 600, marginBottom: "0.5rem" }}>WHOIS & IP Intelligence Pending</div>
        <div style={{ color: "var(--text-muted)", fontSize: "0.875rem" }}>Registration and geolocation data will appear here once the module runs.</div>
      </div>
    );
  }
  if (status === "running") {
    return (
      <div className="empty-state">
        <span className="spinner" style={{ width: 32, height: 32, marginBottom: "1rem" }} />
        <div style={{ fontWeight: 600 }}>Fetching WHOIS & IP Data...</div>
      </div>
    );
  }

  const { registrar, registrantOrg, registrationDate, expirationDate, updatedDate,
    daysUntilExpiry, nameservers = [], domainStatus = [], ipGeo = [] } = data;

  const expiryColor = daysUntilExpiry === null ? "#5a6a80"
    : daysUntilExpiry < 0 ? "#e11d48"
      : daysUntilExpiry <= 30 ? "#ea580c"
        : daysUntilExpiry <= 90 ? "#d97706"
          : "#22c55e";

  const fmtDate = (d) => d ? new Date(d).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }) : "—";

  return (
    <div className="tab-sections">
      <div className="whois-layout">

        {/* Domain Registration Card */}
        <div className="card">
          <div className="card-header">📋 Domain Registration</div>
          <div className="whois-info-grid">
            {[
              { label: "Registrar", value: registrar || "Unknown" },
              { label: "Registrant", value: registrantOrg || "Privacy Protected" },
              { label: "Registered", value: fmtDate(registrationDate) },
              { label: "Updated", value: fmtDate(updatedDate) },
              {
                label: "Expires",
                value: fmtDate(expirationDate),
                extra: daysUntilExpiry !== null
                  ? (daysUntilExpiry < 0 ? "EXPIRED" : `${daysUntilExpiry}d left`)
                  : null,
                color: expiryColor,
              },
            ].map(item => (
              <div key={item.label} className="whois-info-row">
                <span className="whois-info-label">{item.label}</span>
                <span className="whois-info-value" style={item.color ? { color: item.color, fontWeight: 600 } : {}}>
                  {item.value}
                  {item.extra && (
                    <span className="whois-expiry-badge" style={{ background: item.color + "22", color: item.color }}>
                      {item.extra}
                    </span>
                  )}
                </span>
              </div>
            ))}
          </div>

          {nameservers.length > 0 && (
            <div className="whois-ns-section">
              <div className="whois-info-label" style={{ marginBottom: 8 }}>Name Servers</div>
              {nameservers.map(ns => (
                <div key={ns} className="whois-ns-item">{ns}</div>
              ))}
            </div>
          )}
        </div>

        {/* Domain Status Flags */}
        {domainStatus.length > 0 && (
          <div className="card">
            <div className="card-header">🔒 Domain Status Flags</div>
            <div style={{ padding: "12px" }}>
              {domainStatus.map(s => {
                const isGood = s.toLowerCase().includes("prohibited") || s.toLowerCase().includes("ok") || s.toLowerCase().includes("active");
                return (
                  <div key={s} className="dns-check">
                    <span className={`check-icon ${isGood ? "pass" : "warn"}`}>{isGood ? "✓" : "⚠"}</span>
                    <span style={{ fontSize: 12, fontFamily: "monospace", color: "#8896aa" }}>{s}</span>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>

      {/* IP Geolocation */}
      {ipGeo.length > 0 && (
        <div className="card" style={{ marginTop: 16 }}>
          <div className="card-header">🌍 IP Geolocation</div>
          <div className="geo-grid">
            {ipGeo.map(geo => (
              <div key={geo.ip} className="geo-card">
                <div className="geo-card-top">
                  {geo.countryCode && (
                    <img
                      src={`https://flagcdn.com/20x15/${geo.countryCode.toLowerCase()}.png`}
                      alt={geo.country}
                      className="geo-flag"
                      onError={e => { e.target.style.display = "none"; }}
                    />
                  )}
                  <code className="geo-ip">{geo.ip}</code>
                  {geo.isProxy && <span className="geo-badge proxy">PROXY</span>}
                  {geo.isHosting && <span className="geo-badge cloud">CLOUD</span>}
                </div>
                <div className="geo-details">
                  {[
                    { icon: "📍", label: [geo.city, geo.region, geo.country].filter(Boolean).join(", ") },
                    { icon: "🏢", label: geo.isp },
                    { icon: "🏗", label: geo.org },
                    { icon: "🔢", label: geo.asn },
                  ].filter(i => i.label).map((item, idx) => (
                    <div key={idx} className="geo-detail-row">
                      <span className="geo-detail-icon">{item.icon}</span>
                      <span className="geo-detail-value">{item.label}</span>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Web Attacks Tab ───────────────────────────────────────────────────────────
const ATTACK_CATEGORY_ICONS = {
  "XSS": "⚡",
  "SQL Injection": "💉",
  "Command Injection": "💣",
  "Path Traversal": "📂",
  "CRLF Injection": "↩",
  "SSTI": "🧩",
  "Information Disclosure": "🔍",
  "Mixed Content": "🔀",
  "Subresource Integrity": "🔗",
  "Security.txt": "📋",
};

function WebAttacksTab({ data: rawData, status }) {
  const isMulti = rawData?.multiTarget;
  const [selectedTarget, setSelectedTarget] = useState(isMulti ? rawData.targetResults[0]?.domain : null);
  const data = isMulti ? (rawData.targetResults.find(t => t.domain === selectedTarget) || rawData.targetResults[0]) : rawData;

  const [expandedFinding, setExpandedFinding] = useState(null);

  if (status === "pending" || !data) {
    return (
      <div className="empty-state">
        <div style={{ fontSize: "2.5rem", marginBottom: "0.75rem" }}>⚔️</div>
        <div style={{ fontWeight: 600, marginBottom: "0.5rem" }}>Active Web Attack Scan Pending</div>
        <div style={{ color: "var(--text-muted)", fontSize: "0.875rem" }}>
          Wapiti-style fuzzing will start after the previous modules complete.
        </div>
      </div>
    );
  }
  if (status === "running") {
    return (
      <div className="empty-state">
        <span className="spinner" style={{ width: 32, height: 32, marginBottom: "1rem" }} />
        <div style={{ fontWeight: 600 }}>Running Active Vulnerability Probes...</div>
        <div style={{ color: "var(--text-muted)", fontSize: "0.875rem", marginTop: "0.5rem" }}>
          Injecting payloads into URL parameters and forms
        </div>
      </div>
    );
  }

  const { attackSurface = {}, attackResults = [], findings = [], summary = {} } = data;

  // Group attack results by category — take the worst status per category
  const byCategory = {};
  for (const r of attackResults) {
    if (!byCategory[r.category]) byCategory[r.category] = [];
    byCategory[r.category].push(r);
  }

  const categoryRows = Object.entries(byCategory).map(([cat, rows]) => {
    const vulnerable = rows.some(r => r.status === "vulnerable" || r.status === "detected");
    const missing = rows.some(r => r.status === "missing");
    const present = rows.some(r => r.status === "present" || r.status === "ok");
    const status = vulnerable ? "vulnerable" : missing ? "missing" : present ? "ok" : "not detected";
    const target = rows[0]?.target || "";
    const detail = rows.find(r => r.payload)?.payload || rows.find(r => r.detail)?.detail || "—";
    const param = rows.find(r => r.param)?.param || "—";
    return { category: cat, status, target, detail, param, count: rows.length };
  });

  const vulnCount = findings.filter(f => ["critical", "high"].includes(f.severity)).length;
  const totalProbes = attackSurface.testedPoints || summary.totalProbes || 0;
  const [showParams, setShowParams] = useState(false);
  const uniqueParams = Array.from(new Set(attackResults.map(r => r.param).filter(p => p && p !== "—")));

  return (
    <div className="tab-sections">
      <TargetSelector rawData={rawData} selectedTarget={selectedTarget} setSelectedTarget={setSelectedTarget} />

      {/* Responsible use notice */}
      <div className="card" style={{ borderLeft: "4px solid #d97706", background: "var(--card-bg)" }}>
        <div style={{ display: "flex", gap: "0.75rem", alignItems: "flex-start", padding: "0.25rem 0" }}>
          <span style={{ fontSize: "1.25rem" }}>⚠️</span>
          <div>
            <div style={{ fontWeight: 600, color: "#d97706", marginBottom: "0.25rem" }}>Active Scanning — Authorized Use Only</div>
            <div style={{ fontSize: "0.8125rem", color: "var(--text-muted)" }}>
              This module actively injects XSS, SQLi, command injection, and path traversal payloads. Only run against domains you own or have explicit written authorization to test.
            </div>
          </div>
        </div>
      </div>

      {/* Attack surface stats */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))", gap: "1rem" }}>
        {[
          { label: "URL Params Found", value: attackSurface.urlParams || 0, icon: "🔗", onClick: () => setShowParams(!showParams), active: showParams },
          { label: "Forms Found", value: attackSurface.forms || 0, icon: "📝" },
          { label: "Total Probes Sent", value: totalProbes, icon: "📡" },
          { label: "XSS Found", value: summary.xss || 0, icon: "⚡", danger: (summary.xss || 0) > 0 },
          { label: "SQLi Found", value: summary.sqli || 0, icon: "💉", danger: (summary.sqli || 0) > 0 },
          { label: "CMDi Found", value: summary.cmdi || 0, icon: "💣", danger: (summary.cmdi || 0) > 0 },
          { label: "LFI Found", value: summary.lfi || 0, icon: "📂", danger: (summary.lfi || 0) > 0 },
          { label: "Info Disclosure", value: summary.infoDisc || 0, icon: "🔍", danger: (summary.infoDisc || 0) > 0 },
        ].map(item => (
          <div key={item.label}
            className={`stat-card ${item.danger ? "danger" : ""} ${item.active ? "active" : ""}`}
            style={{ padding: "1rem", textAlign: "center", cursor: item.onClick ? "pointer" : "default" }}
            onClick={item.onClick}>
            <div style={{ fontSize: "1.25rem", marginBottom: "0.25rem" }}>{item.icon}</div>
            <div className="stat-value" style={{ fontSize: "1.5rem" }}>{item.value}</div>
            <div className="stat-label" style={{ fontSize: "0.75rem" }}>{item.label}</div>
          </div>
        ))}
      </div>

      {/* Discovered Parameters Panel */}
      {showParams && (
        <div className="card" style={{ padding: "1rem", marginTop: "1rem", borderTop: "2px solid #3b82f6" }}>
          <div style={{ fontWeight: 600, marginBottom: "0.75rem", display: "flex", justifyContent: "space-between" }}>
            <span>Discovered Injectable Parameters</span>
            <button style={{ background: "none", border: "none", color: "var(--text-muted)", cursor: "pointer" }} onClick={() => setShowParams(false)}>✕</button>
          </div>
          {uniqueParams.length > 0 ? (
            <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
              {uniqueParams.map(p => (
                <span key={p} style={{ padding: "4px 8px", background: "rgba(59, 130, 246, 0.15)", color: "#60a5fa", borderRadius: "4px", fontFamily: "monospace", fontSize: 13, border: "1px solid rgba(59, 130, 246, 0.3)" }}>
                  ?{p}=
                </span>
              ))}
            </div>
          ) : (
            <div style={{ color: "var(--text-muted)", fontSize: 13 }}>No unique parameters extracted from probe history.</div>
          )}
        </div>
      )}

      {/* Attack probe results table */}
      {categoryRows.length > 0 && (
        <div className="card">
          <div className="card-header">⚔ Attack Probe Results</div>
          <table className="data-table">
            <thead>
              <tr>
                <th>Category</th>
                <th>Result</th>
                <th>Target / Payload</th>
                <th>Param</th>
              </tr>
            </thead>
            <tbody>
              {categoryRows.map(row => (
                <tr key={row.category}>
                  <td>
                    <span style={{ marginRight: "0.5rem" }}>{ATTACK_CATEGORY_ICONS[row.category] || "🔬"}</span>
                    {row.category}
                  </td>
                  <td>
                    <span className={`status-pill ${row.status === "vulnerable" || row.status === "missing" ? "error" :
                      row.status === "ok" || row.status === "not detected" ? "complete" : "running"
                      }`} style={{ fontSize: "0.75rem" }}>
                      {row.status === "vulnerable" ? "⚠ VULNERABLE" :
                        row.status === "missing" ? "✗ MISSING" :
                          row.status === "detected" ? "⚠ DETECTED" :
                            row.status === "ok" || row.status === "present" ? "✓ OK" : "✓ Not Detected"}
                    </span>
                  </td>
                  <td className="banner-cell" style={{ maxWidth: 260, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    <span title={row.detail}>{row.detail}</span>
                  </td>
                  <td><code>{row.param !== "—" ? row.param : "—"}</code></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Active scan findings */}
      {findings.length > 0 && (
        <div className="card">
          <div className="card-header">🚨 Active Scan Findings ({findings.length})</div>
          <div className="findings-list">
            {[...findings]
              .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5))
              .map(f => (
                <div
                  key={f.id}
                  className={`finding-card ${f.severity} ${expandedFinding === f.id ? "expanded" : ""}`}
                  onClick={() => setExpandedFinding(expandedFinding === f.id ? null : f.id)}
                >
                  <div className="finding-card-header">
                    <SeverityBadge severity={f.severity} />
                    <span className="finding-card-title">{f.title}</span>
                    <span className="finding-module-tag">{ATTACK_CATEGORY_ICONS[f.category] || "⚔"} wapiti</span>
                    <span className="expand-icon">{expandedFinding === f.id ? "▲" : "▼"}</span>
                  </div>
                  {expandedFinding === f.id && (
                    <div className="finding-card-body">
                      <div className="finding-section">
                        <div className="finding-section-label">Description</div>
                        <div>{f.description}</div>
                      </div>
                      {f.affected && (
                        <div className="finding-section">
                          <div className="finding-section-label">Affected URL</div>
                          <code style={{ wordBreak: "break-all" }}>{f.affected}</code>
                        </div>
                      )}
                      {f.remediation && (
                        <div className="finding-section remediation">
                          <div className="finding-section-label">Remediation</div>
                          <div>{f.remediation}</div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ))}
          </div>
        </div>
      )}

      {findings.length === 0 && status === "complete" && (
        <div className="card" style={{ textAlign: "center", padding: "2.5rem" }}>
          <div style={{ fontSize: "2.5rem", marginBottom: "0.75rem" }}>✅</div>
          <div style={{ fontWeight: 600, marginBottom: "0.5rem" }}>No Active Vulnerabilities Detected</div>
          <div style={{ color: "var(--text-muted)", fontSize: "0.875rem" }}>
            {totalProbes} probe(s) sent across {attackSurface.urlParams || 0} URL parameter(s) and {attackSurface.forms || 0} form(s). No XSS, SQLi, CMDi, LFI, CRLF, or SSTI was found.
          </div>
        </div>
      )}
    </div>
  );
}

// ── Live Log Tab ──────────────────────────────────────────────────────────────
function LiveLogTab({ logs }) {
  const endRef = useRef(null);
  useEffect(() => { endRef.current?.scrollIntoView({ behavior: "smooth" }); }, [logs]);

  return (
    <div className="log-container">
      {logs.length === 0 && <div className="log-empty">Waiting for scan activity...</div>}
      {logs.map((log, i) => (
        <div key={i} className={`log-line ${log.event || ""}`}>
          <span className="log-time">{log.time}</span>
          <span className="log-event">{log.event}</span>
          <span className="log-message">{log.message || log.label || log.error || JSON.stringify(log)}</span>
        </div>
      ))}
      <div ref={endRef} />
    </div>
  );
}

// ── History View ──────────────────────────────────────────────────────────────
function HistoryView({ scans, onSelectScan, compareIds, setCompareIds, onCompare }) {
  const toggleCompare = (id) => {
    setCompareIds(prev => {
      if (prev.includes(id)) return prev.filter(x => x !== id);
      if (prev.length >= 2) return [prev[1], id];
      return [...prev, id];
    });
  };

  return (
    <div className="view-content">
      <div className="page-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 12 }}>
        <div>
          <h1>Scan History</h1>
          <p className="page-sub">Select up to 2 completed scans to compare remediation progress</p>
        </div>
        {compareIds.length === 2 && (
          <button className="scan-btn" style={{ padding: "8px 18px", alignSelf: "flex-start" }} onClick={onCompare}>
            ⚖ Compare Selected
          </button>
        )}
      </div>

      {compareIds.length > 0 && (
        <div className="compare-banner">
          <span className="compare-banner-label">⚖ Comparing:</span>
          {compareIds.map(id => {
            const s = scans.find(x => x.id === id);
            return s ? <code key={id} className="compare-banner-domain">{s.domain}</code> : null;
          })}
          {compareIds.length === 1 && <span style={{ color: "var(--text-muted)", fontSize: 12 }}>Select one more scan to compare</span>}
          <button className="compare-banner-clear" onClick={() => setCompareIds([])}>✕ Clear</button>
        </div>
      )}

      <div className="card">
        <table className="data-table">
          <thead>
            <tr>
              <th style={{ width: 44 }}></th>
              <th>Domain</th><th>Status</th><th>Risk Score</th><th>Findings</th><th>Duration</th><th>Date</th>
            </tr>
          </thead>
          <tbody>
            {scans.map(s => {
              const duration = s.completedAt
                ? Math.round((new Date(s.completedAt) - new Date(s.startedAt)) / 1000)
                : null;
              const isComplete = s.status === "complete";
              const isSelected = compareIds.includes(s.id);
              return (
                <tr key={s.id}
                  className={`table-row ${isSelected ? "compare-selected-row" : ""}`}
                  onClick={() => isComplete ? toggleCompare(s.id) : onSelectScan(s.id)}>
                  <td style={{ paddingLeft: 16 }}>
                    {isComplete && (
                      <div className={`compare-checkbox ${isSelected ? "checked" : ""}`}>
                        {isSelected ? "✓" : ""}
                      </div>
                    )}
                  </td>
                  <td className="domain-cell">{s.domain}</td>
                  <td><span className={`status-pill ${s.status}`}>{s.status}</span></td>
                  <td>{s.riskScore ? <RiskGrade grade={s.riskScore.grade} score={s.riskScore.score} /> : "—"}</td>
                  <td>
                    {s.riskScore?.breakdown && (
                      <span className="findings-count">
                        {Object.entries(s.riskScore.breakdown).map(([sev, count]) =>
                          count > 0 ? <span key={sev} className={`fc ${sev}`}>{count}{sev[0].toUpperCase()}</span> : null
                        )}
                      </span>
                    )}
                  </td>
                  <td>{duration ? `${duration}s` : "—"}</td>
                  <td className="time-cell">{new Date(s.startedAt).toLocaleDateString()}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── Compare View ──────────────────────────────────────────────────────────────
const SEVERITY_SORT = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function CompareView({ scanAId, scanBId, onClose }) {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetch(`${API_BASE}/scan/compare?a=${scanAId}&b=${scanBId}`)
      .then(r => r.json())
      .then(data => { if (data.error) setError(data.error); else setResult(data); setLoading(false); })
      .catch(e => { setError(e.message); setLoading(false); });
  }, [scanAId, scanBId]);

  if (loading) return (
    <div className="view-content">
      <div className="empty-state" style={{ padding: "80px 0" }}>
        <span className="spinner" style={{ width: 32, height: 32, marginBottom: "1rem" }} />
        <div>Loading comparison...</div>
      </div>
    </div>
  );

  if (error || !result) return (
    <div className="view-content">
      <div className="empty-state" style={{ padding: "60px 0" }}>
        <div style={{ fontSize: "2.5rem" }}>⚠️</div>
        <div style={{ fontWeight: 600, marginTop: "1rem" }}>Comparison Failed</div>
        <div style={{ color: "var(--text-muted)", marginTop: "0.5rem" }}>{error}</div>
        <button className="scan-btn" style={{ marginTop: "1.5rem" }} onClick={onClose}>← Back to History</button>
      </div>
    </div>
  );

  const { scanA, scanB, scoreChange, newFindings, resolvedFindings, sharedFindings, summary } = result;
  const improved = scoreChange < 0;
  const deltaColor = scoreChange < 0 ? "#22c55e" : scoreChange > 0 ? "#e11d48" : "#5a6a80";

  const FindingRow = ({ f, badge }) => (
    <div className={`finding-card ${f.severity}`} style={{ opacity: badge === "fixed" ? 0.7 : 1 }}>
      <div className="finding-card-header">
        <SeverityBadge severity={f.severity} />
        <span className="finding-card-title" style={badge === "fixed" ? { textDecoration: "line-through", opacity: 0.75 } : {}}>
          {f.title}
        </span>
        <span className="finding-module-tag">{f.module}</span>
        {badge === "new" && <span className="compare-badge new">NEW</span>}
        {badge === "fixed" && <span className="compare-badge fixed">FIXED</span>}
      </div>
    </div>
  );

  return (
    <div className="view-content">
      <div className="page-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div>
          <h1>⚖ Scan Comparison</h1>
          <p className="page-sub">Side-by-side analysis to track remediation progress and regressions</p>
        </div>
        <button className="export-btn" onClick={onClose}>← Back to History</button>
      </div>

      {/* A vs B cards */}
      <div className="compare-header-grid">
        {[{ scan: scanA, label: "Scan A — Baseline" }, { scan: scanB, label: "Scan B — Current" }].map(({ scan, label }) => (
          <div key={scan.id} className="card compare-scan-card">
            <div className="card-header">{label}</div>
            <div style={{ padding: "16px", display: "flex", alignItems: "center", gap: 16 }}>
              {scan.riskScore && <RiskScoreCard riskScore={scan.riskScore} />}
              <div>
                <div style={{ fontFamily: "monospace", color: "#60a5fa", fontSize: 14, fontWeight: 600 }}>{scan.domain}</div>
                <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 4 }}>{new Date(scan.startedAt).toLocaleString()}</div>
                <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 2 }}>{scan.findingCount} total findings</div>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Delta summary */}
      <div className="card compare-delta-card" style={{ borderLeft: `4px solid ${deltaColor}` }}>
        <div className="compare-delta-body">
          <div style={{ textAlign: "center" }}>
            <div className="compare-delta-num" style={{ color: deltaColor }}>{scoreChange > 0 ? "+" : ""}{scoreChange}</div>
            <div style={{ fontSize: 11, color: "var(--text-muted)" }}>Risk Score Change</div>
            <div style={{ fontSize: 13, fontWeight: 700, marginTop: 4, color: deltaColor }}>
              {improved ? "✅ Improved" : scoreChange === 0 ? "➡ Unchanged" : "🔴 Regressed"}
            </div>
          </div>
          <div className="compare-summary-pills">
            {[
              { label: "New", value: summary.newCount, color: "#e11d48", icon: "🔴" },
              { label: "Resolved", value: summary.resolvedCount, color: "#22c55e", icon: "✅" },
              { label: "Shared", value: summary.sharedCount, color: "#d97706", icon: "⚠️" },
            ].map(item => (
              <div key={item.label} className="compare-pill">
                <div>{item.icon}</div>
                <div style={{ fontSize: "1.75rem", fontWeight: 700, color: item.color }}>{item.value}</div>
                <div style={{ fontSize: 11, color: "var(--text-muted)" }}>{item.label}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* New Findings */}
      {newFindings.length > 0 && (
        <div className="card">
          <div className="card-header" style={{ color: "#f87171" }}>🔴 New Findings ({newFindings.length}) — Regressions since Scan A</div>
          <div className="findings-list" style={{ padding: "8px" }}>
            {[...newFindings].sort((a, b) => (SEVERITY_SORT[a.severity] ?? 5) - (SEVERITY_SORT[b.severity] ?? 5))
              .map(f => <FindingRow key={f.id} f={f} badge="new" />)}
          </div>
        </div>
      )}

      {/* Resolved Findings */}
      {resolvedFindings.length > 0 && (
        <div className="card">
          <div className="card-header" style={{ color: "#4ade80" }}>✅ Resolved Findings ({resolvedFindings.length}) — Fixed since Scan A</div>
          <div className="findings-list" style={{ padding: "8px" }}>
            {[...resolvedFindings].sort((a, b) => (SEVERITY_SORT[a.severity] ?? 5) - (SEVERITY_SORT[b.severity] ?? 5))
              .map(f => <FindingRow key={f.id} f={f} badge="fixed" />)}
          </div>
        </div>
      )}

      {/* Shared Findings */}
      {sharedFindings.length > 0 && (
        <div className="card">
          <div className="card-header" style={{ color: "#d97706" }}>⚠️ Still Present ({sharedFindings.length}) — In both scans</div>
          <div className="findings-list" style={{ padding: "8px" }}>
            {[...sharedFindings].sort((a, b) => (SEVERITY_SORT[a.severity] ?? 5) - (SEVERITY_SORT[b.severity] ?? 5))
              .map(f => <FindingRow key={f.id} f={f} />)}
          </div>
        </div>
      )}
    </div>
  );
}


function RiskGrade({ grade, score, small }) {
  const color = grade === "A+" || grade === "A" ? "#16a34a" :
    grade === "B" ? "#65a30d" : grade === "C" ? "#d97706" :
      grade === "D" ? "#ea580c" : grade === "E" ? "#dc2626" : "#9f1239";
  return (
    <span className={`risk-grade ${small ? "small" : ""}`} style={{ color, borderColor: color + "30" }}>
      {grade} {score !== undefined && !small ? <span className="grade-score">({score})</span> : null}
    </span>
  );
}

function RiskScoreCard({ riskScore }) {
  return (
    <div className="risk-score-card" style={{ borderColor: riskScore.color + "40" }}>
      <div className="risk-score-num" style={{ color: riskScore.color }}>{riskScore.score}</div>
      <div className="risk-score-label">{riskScore.label}</div>
      <div className="risk-grade-big" style={{ color: riskScore.color }}>{riskScore.grade}</div>
    </div>
  );
}

function StatCard({ label, value, accent }) {
  return (
    <div className={`stat-card ${accent || ""}`}>
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

function SummaryItem({ label, value, accent }) {
  return (
    <div className={`summary-item ${accent ? "accent" : ""}`}>
      <span className="summary-num">{value}</span>
      <span className="summary-label">{label}</span>
    </div>
  );
}

// ── WAF/CDN Detector Tab ──────────────────────────────────────────────────────
function WAFDetectorTab({ data: rawData, status }) {
  const isMulti = rawData?.multiTarget;
  const [selectedTarget, setSelectedTarget] = useState(isMulti ? rawData.targetResults[0]?.domain : null);
  const data = isMulti ? (rawData.targetResults.find(t => t.domain === selectedTarget) || rawData.targetResults[0]) : rawData;

  const [expanded, setExpanded] = useState(null);
  if (!data || status === "pending") return (
    <div className="empty-state">
      <div style={{ fontSize: "2rem", marginBottom: "0.5rem" }}>🛡️</div>
      <div style={{ fontWeight: 600, marginBottom: "0.25rem" }}>WAF/CDN Detection Pending</div>
      <div style={{ color: "var(--text-muted)", fontSize: "0.875rem" }}>Will run after Asset Discovery.</div>
    </div>
  );
  if (status === "running") return (
    <div className="empty-state">
      <span className="spinner" style={{ width: 28, height: 28, marginBottom: "1rem" }} />
      <div style={{ fontWeight: 600 }}>Fingerprinting Security Infrastructure...</div>
    </div>
  );

  const { detected = [], behaviorBlocked = [], isProtected, summary = {} } = data;

  return (
    <div className="tab-sections">
      <TargetSelector rawData={rawData} selectedTarget={selectedTarget} setSelectedTarget={setSelectedTarget} />
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: "12px" }}>
        <StatCard label="WAFs Detected" value={summary.wafCount} accent={summary.wafCount > 0 ? "success" : ""} />
        <StatCard label="CDNs Detected" value={summary.cdnCount} accent={summary.cdnCount > 0 ? "success" : ""} />
        <StatCard label="Load Balancers" value={summary.lbCount} />
        <StatCard label="Payloads Blocked" value={`${summary.blocked}/${summary.behaviorTests}`} accent={summary.blocked > 0 ? "success" : "danger"} />
      </div>

      <div className="card">
        <div className="card-header">🛡 Detected Infrastructure</div>
        {detected.length === 0 ? (
          <div style={{ padding: "2rem", textAlign: "center", color: "var(--text-muted)" }}>
            No WAF, CDN, or Load Balancer products were fingerprinted.
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: "1px", background: "var(--border-color)" }}>
            {detected.map((d, i) => (
              <div key={i} style={{ background: "var(--bg-card)", padding: "16px", display: "flex", alignItems: "flex-start", gap: "16px" }}>
                <div style={{ fontSize: "2rem", filter: "grayscale(0.5)" }}>
                  {d.type?.includes("WAF") ? "🧱" : d.type?.includes("CDN") ? "⚡" : "⚖"}
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}>
                    <h3 style={{ margin: 0, fontSize: "16px" }}>{d.name}</h3>
                    <span style={{ fontSize: "11px", background: "var(--bg-lighter)", padding: "2px 8px", borderRadius: "10px" }}>{d.type}</span>
                    {d.confidence === "high" && <span style={{ fontSize: "11px", color: "#22c55e", background: "#16653430", padding: "2px 8px", borderRadius: "10px" }}>High Confidence</span>}
                  </div>
                  <div style={{ fontSize: "13px", color: "var(--text-muted)", marginBottom: "8px" }}>{d.sig?.description || d.name}</div>
                  <div style={{ fontSize: "12px", background: "var(--bg-lighter)", padding: "8px", borderRadius: "4px", color: "#e2e8f0" }}>
                    <strong>Detection Methods:</strong> {d.methods?.join(", ") || "Header fingerprint"}
                  </div>
                  {d.sig?.bypass_hint && (
                    <div style={{ fontSize: "12px", color: "#60a5fa", marginTop: "8px" }}>💡 <strong>Bypass Hint:</strong> {d.sig.bypass_hint}</div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="card">
        <div className="card-header">🧪 Active Behavior Tests</div>
        <table className="data-table">
          <thead><tr><th>Test Payload</th><th>Result</th><th>HTTP Status</th></tr></thead>
          <tbody>
            {behaviorBlocked.length === 0 ? (
              <tr><td colSpan="3" style={{ textAlign: "center", padding: "16px", color: "var(--text-muted)" }}>None of the test payloads were blocked.</td></tr>
            ) : behaviorBlocked.map((b, i) => (
              <tr key={i}>
                <td>{b.test}</td>
                <td><span className="status-pill error">⚠ BLOCKED</span></td>
                <td><code>HTTP {b.status}</code></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── JS Secrets Tab ──────────────────────────────────────────────────────────────
function JSSecretTab({ data: rawData, status }) {
  const isMulti = rawData?.multiTarget;
  const [selectedTarget, setSelectedTarget] = useState(isMulti ? rawData.targetResults[0]?.domain : null);
  const data = isMulti ? (rawData.targetResults.find(t => t.domain === selectedTarget) || rawData.targetResults[0]) : rawData;

  const [expanded, setExpanded] = useState(null);

  if (!data || status === "pending") return (
    <div className="empty-state">
      <div style={{ fontSize: "2rem", marginBottom: "0.5rem" }}>🔑</div>
      <div style={{ fontWeight: 600, marginBottom: "0.25rem" }}>JS Secret Scan Pending</div>
      <div style={{ color: "var(--text-muted)", fontSize: "0.875rem" }}>Will scan discovered JS bundles for secrets.</div>
    </div>
  );
  if (status === "running") return (
    <div className="empty-state">
      <span className="spinner" style={{ width: 28, height: 28, marginBottom: "1rem" }} />
      <div style={{ fontWeight: 600 }}>Analyzing JavaScript files for embedded secrets...</div>
    </div>
  );

  const { secrets = [], highEntropyStrings = [], summary = {} } = data;

  return (
    <div className="tab-sections">
      <TargetSelector rawData={rawData} selectedTarget={selectedTarget} setSelectedTarget={setSelectedTarget} />
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: "12px" }}>
        <StatCard label="Files Scanned" value={summary.filesScanned} />
        <StatCard label="Secrets Found" value={summary.secretsFound} accent={summary.secretsFound > 0 ? "danger" : ""} />
        <StatCard label="High Entropy Hits" value={summary.highEntropyHits} accent={summary.highEntropyHits > 0 ? "warning" : ""} />
      </div>

      {secrets.length > 0 && (
        <div className="card">
          <div className="card-header" style={{ color: "#f87171" }}>🚨 Exposed Secrets ({secrets.length})</div>
          <div className="findings-list">
            {secrets.map((s, i) => {
              const id = `${s.patternId}-${i}`;
              return (
                <div key={id} className={`finding-card ${s.severity} ${expanded === id ? "expanded" : ""}`} onClick={() => setExpanded(expanded === id ? null : id)}>
                  <div className="finding-card-header">
                    <SeverityBadge severity={s.severity} />
                    <span className="finding-card-title">{s.name}</span>
                    <span className="finding-module-tag">{s.patternId}</span>
                    <span className="expand-icon">{expanded === id ? "▲" : "▼"}</span>
                  </div>
                  {expanded === id && (
                    <div className="finding-card-body">
                      <div className="finding-section">
                        <div className="finding-section-label">Masked Value</div>
                        <code style={{ fontSize: "14px", color: "#f87171" }}>{s.maskedValue}</code>
                      </div>
                      <div className="finding-section">
                        <div className="finding-section-label">Location</div>
                        <div style={{ fontSize: "13px", wordBreak: "break-all" }}>
                          <a href={s.fileUrl} target="_blank" rel="noreferrer" style={{ color: "#60a5fa" }}>{s.fileUrl}</a> (Line ~{s.lineNumber})
                        </div>
                      </div>
                      <div className="finding-section">
                        <div className="finding-section-label">Context snippet</div>
                        <pre style={{ margin: 0, padding: "8px", background: "var(--bg-main)", borderRadius: "4px", fontSize: "11px", whiteSpace: "pre-wrap", color: "#e2e8f0" }}>
                          {s.context}
                        </pre>
                      </div>
                      <div className="finding-section remediation">
                        <div className="finding-section-label">Remediation</div>
                        {s.fix}
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      <div className="card">
        <div className="card-header">🎲 High-Entropy Strings (Possible Secrets)</div>
        <table className="data-table">
          <thead><tr><th>Value (Truncated)</th><th>Entropy</th><th>Source</th></tr></thead>
          <tbody>
            {highEntropyStrings.length === 0 ? (
              <tr><td colSpan="3" style={{ textAlign: "center", padding: "16px", color: "var(--text-muted)" }}>No high-entropy strings detected.</td></tr>
            ) : highEntropyStrings.map((h, i) => (
              <tr key={i}>
                <td><code style={{ fontSize: "11px", color: "#d97706" }}>{h.value}</code></td>
                <td>{h.entropy}</td>
                <td style={{ fontSize: "11px", maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={h.source}>{h.source}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── Subdomain Takeover Tab ────────────────────────────────────────────────────
function TakeoverTab({ data: rawData, status }) {
  const isMulti = rawData?.multiTarget;
  const [selectedTarget, setSelectedTarget] = useState(isMulti ? rawData.targetResults[0]?.domain : null);
  const data = isMulti ? (rawData.targetResults.find(t => t.domain === selectedTarget) || rawData.targetResults[0]) : rawData;

  if (!data || status === "pending") return (
    <div className="empty-state">
      <div style={{ fontSize: "2rem", marginBottom: "0.5rem" }}>⚠️</div>
      <div style={{ fontWeight: 600, marginBottom: "0.25rem" }}>Takeover Scan Pending</div>
      <div style={{ color: "var(--text-muted)", fontSize: "0.875rem" }}>Checking subdomains for dangling CNAMEs.</div>
    </div>
  );
  if (status === "running") return (
    <div className="empty-state">
      <span className="spinner" style={{ width: 28, height: 28, marginBottom: "1rem" }} />
      <div style={{ fontWeight: 600 }}>Analyzing DNS CNAME chains for takeover vulnerabilities...</div>
    </div>
  );

  const { checked = [], vulnerable = [], summary = {} } = data;

  return (
    <div className="tab-sections">
      <TargetSelector rawData={rawData} selectedTarget={selectedTarget} setSelectedTarget={setSelectedTarget} />
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: "12px" }}>
        <StatCard label="Subdomains Checked" value={summary.checked} />
        <StatCard label="Services Fingerprints" value={summary.servicesScanned} />
        <StatCard label="Vulnerable" value={summary.vulnerable} accent={summary.vulnerable > 0 ? "danger" : "success"} />
      </div>

      {vulnerable.length > 0 && (
        <div className="card" style={{ border: "1px solid #e11d48" }}>
          <div className="card-header" style={{ color: "#e11d48", borderBottom: "1px solid #e11d4840" }}>🚨 Vulnerable Subdomains ({vulnerable.length})</div>
          <table className="data-table">
            <thead><tr><th>Subdomain</th><th>Service</th><th>CNAME Chain</th></tr></thead>
            <tbody>
              {vulnerable.map((v, i) => (
                <tr key={i} style={{ background: "#e11d4810" }}>
                  <td style={{ fontWeight: 600 }}>{v.subdomain}</td>
                  <td><span className="status-pill error">{v.service}</span></td>
                  <td style={{ fontSize: "11px", color: "var(--text-muted)" }}>{v.cnameChain.join(" → ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="card">
        <div className="card-header">🔍 Checked CNAME Records</div>
        <table className="data-table">
          <thead><tr><th>Subdomain</th><th>Final Target</th><th>Status</th></tr></thead>
          <tbody>
            {checked.length === 0 ? (
              <tr><td colSpan="3" style={{ textAlign: "center", padding: "16px", color: "var(--text-muted)" }}>No subdomains checked.</td></tr>
            ) : checked.map((c, i) => (
              <tr key={i}>
                <td>{c.subdomain}</td>
                <td style={{ fontSize: "11px" }}>{c.cnameTarget || "—"}</td>
                <td>
                  {c.cnameChain?.length < 2 ? <span className="status-pill">No CNAME</span> :
                    c.targetNXDOMAIN ? <span className="status-pill warning">NXDOMAIN</span> :
                      <span className="status-pill complete">Resolves (HTTP {c.status})</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── CMS Scan Tab ──────────────────────────────────────────────────────────────
function CMSScanTab({ data: rawData, status }) {
  const isMulti = rawData?.multiTarget;
  const [selectedTarget, setSelectedTarget] = useState(isMulti ? rawData.targetResults[0]?.domain : null);
  const data = isMulti ? (rawData.targetResults.find(t => t.domain === selectedTarget) || rawData.targetResults[0]) : rawData;

  const [expanded, setExpanded] = useState(null);
  if (!data || status === "pending") return (
    <div className="empty-state">
      <div style={{ fontSize: "2rem", marginBottom: "0.5rem" }}>🏛️</div>
      <div style={{ fontWeight: 600, marginBottom: "0.25rem" }}>CMS Scan Pending</div>
      <div style={{ color: "var(--text-muted)", fontSize: "0.875rem" }}>Will run after web tech fingerprinting completes.</div>
    </div>
  );
  if (status === "running") return (
    <div className="empty-state"><span className="spinner" style={{ width: 28, height: 28, marginBottom: "1rem" }} />
      <div style={{ fontWeight: 600 }}>Detecting CMS & Running Targeted Checks...</div></div>
  );
  const { detectedPlatforms = [], checks = [], findings = [], summary = {} } = data;
  return (
    <div className="tab-sections">
      <TargetSelector rawData={rawData} selectedTarget={selectedTarget} setSelectedTarget={setSelectedTarget} />
      <div style={{ display: "flex", gap: "10px", flexWrap: "wrap" }}>
        {detectedPlatforms.length === 0
          ? <div className="card" style={{ padding: "1rem", color: "var(--text-muted)" }}>No known CMS/framework detected.</div>
          : detectedPlatforms.map(p => (
            <div key={p.name} className="card" style={{ padding: "12px 20px", display: "flex", alignItems: "center", gap: "10px" }}>
              <span style={{ fontSize: "1.5rem" }}>{p.icon}</span>
              <div><div style={{ fontWeight: 700 }}>{p.name}</div><div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Detected</div></div>
            </div>
          ))}
      </div>
      {summary.checksRun > 0 && (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: "12px" }}>
          {[{ label: "Checks Run", value: summary.checksRun, icon: "🔬" }, { label: "Passed", value: summary.passed, icon: "✅" },
          { label: "Failed", value: summary.failed, icon: "❌", danger: summary.failed > 0 }, { label: "Findings", value: findings.length, icon: "🚨", danger: findings.length > 0 }]
            .map(item => (
              <div key={item.label} className={`stat-card ${item.danger ? "danger" : ""}`} style={{ padding: "1rem", textAlign: "center" }}>
                <div style={{ fontSize: "1.25rem" }}>{item.icon}</div>
                <div className="stat-value" style={{ fontSize: "1.5rem" }}>{item.value}</div>
                <div className="stat-label" style={{ fontSize: "0.75rem" }}>{item.label}</div>
              </div>
            ))}
        </div>
      )}
      {checks.length > 0 && (
        <div className="card">
          <div className="card-header">🔍 CMS-Specific Checks</div>
          <table className="data-table">
            <thead><tr><th>Platform</th><th>Check</th><th>Path</th><th>Result</th><th>HTTP</th></tr></thead>
            <tbody>{checks.map((c, i) => (
              <tr key={i}>
                <td><code style={{ fontSize: "11px" }}>{c.platform}</code></td>
                <td style={{ fontSize: "13px" }}>{c.name}</td>
                <td><code style={{ fontSize: "11px", color: "#60a5fa" }}>{c.path}</code></td>
                <td><span className={`status-pill ${c.status === "fail" ? "error" : "complete"}`}>{c.status === "fail" ? "⚠ FOUND" : "✓ CLEAR"}</span></td>
                <td style={{ fontSize: "12px", color: "#5a6a80" }}>{c.httpStatus || "—"}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      )}
      {findings.length > 0 && (
        <div className="card">
          <div className="card-header">🚨 CMS Findings ({findings.length})</div>
          <div className="findings-list" style={{ padding: "8px" }}>
            {[...findings].sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5)).map(f => (
              <div key={f.id} className={`finding-card ${f.severity} ${expanded === f.id ? "expanded" : ""}`} onClick={() => setExpanded(expanded === f.id ? null : f.id)}>
                <div className="finding-card-header">
                  <SeverityBadge severity={f.severity} />
                  <span className="finding-card-title">{f.title}</span>
                  {f.owasp && <span className="finding-module-tag">{f.owasp}</span>}
                  <span className="expand-icon">{expanded === f.id ? "▲" : "▼"}</span>
                </div>
                {expanded === f.id && (
                  <div className="finding-card-body">
                    <div className="finding-section"><div className="finding-section-label">Description</div>{f.description}</div>
                    {f.affected && <div className="finding-section"><div className="finding-section-label">Affected</div><code style={{ wordBreak: "break-all" }}>{f.affected}</code></div>}
                    {f.remediation && <div className="finding-section remediation"><div className="finding-section-label">Remediation</div>{f.remediation}</div>}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
      {findings.length === 0 && status === "complete" && (
        <div className="card" style={{ textAlign: "center", padding: "2.5rem" }}>
          <div style={{ fontSize: "2.5rem" }}>✅</div>
          <div style={{ fontWeight: 600, marginTop: "0.5rem" }}>No CMS-Specific Vulnerabilities Found</div>
          <div style={{ color: "var(--text-muted)", fontSize: "0.875rem", marginTop: "0.25rem" }}>{summary.checksRun || 0} checks run</div>
        </div>
      )}
    </div>
  );
}

// ── Vuln Assessment Tab ───────────────────────────────────────────────────────
function VulnAssessmentTab({ data: rawData, status }) {
  const isMulti = rawData?.multiTarget;
  const [selectedTarget, setSelectedTarget] = useState(
    isMulti ? rawData.targetResults[0]?.domain : null
  );
  const data = isMulti
    ? (rawData.targetResults.find(t => t.domain === selectedTarget) || rawData.targetResults[0])
    : rawData;
  const [expanded, setExpanded] = useState(null);
  const [filterCat, setFilterCat] = useState("all");

  if (!data || status === "pending") return (
    <div className="empty-state">
      <div style={{ fontSize: "2rem", marginBottom: "0.5rem" }}>🛡</div>
      <div style={{ fontWeight: 600, marginBottom: "0.25rem" }}>Vulnerability Assessment Pending</div>
      <div style={{ color: "var(--text-muted)", fontSize: "0.875rem" }}>Checking HTTP security headers, cookies, SSL, sensitive files, and more.</div>
    </div>
  );
  if (status === "running") return (
    <div className="empty-state">
      <span className="spinner" style={{ width: 28, height: 28, marginBottom: "1rem" }} />
      <div style={{ fontWeight: 600 }}>Running vulnerability checks (120+ probes)...</div>
    </div>
  );

  const { checks = [], findings = [], summary = {} } = data;
  const STATUS_COLORS = { pass: "#22c55e", fail: "#e11d48", warn: "#d97706", info: "#0284c7" };
  const STATUS_ICONS = { pass: "✓", fail: "✗", warn: "⚠", info: "ℹ" };

  // Gather unique categories for filter
  const cats = ["all", ...new Set(checks.map(c => c.category))];
  const filteredChecks = filterCat === "all" ? checks : checks.filter(c => c.category === filterCat);

  return (
    <div className="tab-sections">
      <TargetSelector rawData={rawData} selectedTarget={selectedTarget} setSelectedTarget={setSelectedTarget} />

      {/* Summary bar */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: "12px" }}>
        {[
          { label: "Passed", value: summary.pass, color: "#22c55e" },
          { label: "Failed", value: summary.fail, color: "#e11d48" },
          { label: "Warnings", value: summary.warn, color: "#d97706" },
          { label: "Info", value: summary.info, color: "#0284c7" },
        ].map(s => (
          <div key={s.label} className="card" style={{ padding: "14px", textAlign: "center", borderTop: `3px solid ${s.color}` }}>
            <div style={{ fontSize: "1.8rem", fontWeight: 700, color: s.color }}>{s.value ?? 0}</div>
            <div style={{ fontSize: "12px", color: "var(--text-muted)", marginTop: "2px" }}>{s.label}</div>
          </div>
        ))}
      </div>

      {/* Category filter pills */}
      <div style={{ display: "flex", gap: "6px", flexWrap: "wrap", marginTop: "4px" }}>
        {cats.map(c => (
          <button key={c} onClick={() => setFilterCat(c)}
            style={{ padding: "4px 12px", borderRadius: "12px", border: `1px solid ${filterCat === c ? "#3b82f6" : "#1e2a40"}`, background: filterCat === c ? "#1a3050" : "transparent", cursor: "pointer", fontSize: "12px", color: filterCat === c ? "#60a5fa" : "var(--text-muted)" }}>
            {c === "all" ? "All Categories" : c}
          </button>
        ))}
      </div>

      {/* Checks table */}
      <div className="card">
        <div className="card-header">🔍 Security Checks ({filteredChecks.length})</div>
        <table className="data-table">
          <thead><tr><th>Category</th><th>Check</th><th>Status</th><th>Value</th></tr></thead>
          <tbody>
            {filteredChecks.length === 0 ? (
              <tr><td colSpan="4" style={{ textAlign: "center", padding: "16px", color: "var(--text-muted)" }}>No checks in this category.</td></tr>
            ) : filteredChecks.map((c, i) => (
              <tr key={i}>
                <td><span style={{ fontSize: "11px", color: "var(--text-muted)" }}>{c.category}</span></td>
                <td style={{ fontWeight: 500, fontSize: "13px" }}>{c.name}</td>
                <td>
                  <span style={{ display: "inline-flex", alignItems: "center", gap: "4px", padding: "2px 8px", borderRadius: "10px", fontSize: "11px", fontWeight: 600, color: STATUS_COLORS[c.status] || "#5a6a80", background: `${STATUS_COLORS[c.status] || "#5a6a80"}15` }}>
                    {STATUS_ICONS[c.status] || "?"} {c.status?.toUpperCase()}
                  </span>
                </td>
                <td><code style={{ fontSize: "11px", color: c.status === "fail" ? "#f87171" : "var(--text-muted)", wordBreak: "break-all" }}>{c.value}</code></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Findings */}
      {findings.length > 0 && (
        <div className="card">
          <div className="card-header">🚨 Vulnerability Findings ({findings.length})</div>
          <div className="findings-list" style={{ padding: "8px" }}>
            {[...findings].sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5)).map(f => (
              <div key={f.id} className={`finding-card ${f.severity} ${expanded === f.id ? "expanded" : ""}`} onClick={() => setExpanded(expanded === f.id ? null : f.id)}>
                <div className="finding-card-header">
                  <SeverityBadge severity={f.severity} />
                  <span className="finding-card-title">{f.title}</span>
                  <span className="expand-icon">{expanded === f.id ? "▲" : "▼"}</span>
                </div>
                {expanded === f.id && (
                  <div className="finding-card-body">
                    <div className="finding-section"><div className="finding-section-label">Description</div>{f.description}</div>
                    {f.affected && <div className="finding-section"><div className="finding-section-label">Affected</div><code style={{ wordBreak: "break-all" }}>{f.affected}</code></div>}
                    {f.remediation && <div className="finding-section remediation"><div className="finding-section-label">Remediation</div>{f.remediation}</div>}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
      {findings.length === 0 && status === "complete" && (
        <div className="card" style={{ textAlign: "center", padding: "2.5rem" }}>
          <div style={{ fontSize: "2.5rem" }}>✅</div>
          <div style={{ fontWeight: 600, marginTop: "0.5rem" }}>No Vulnerabilities Found</div>
          <div style={{ color: "var(--text-muted)", fontSize: "0.875rem", marginTop: "0.25rem" }}>{checks.length} checks run, {summary.pass ?? 0} passed</div>
        </div>
      )}
    </div>
  );
}

// ── CVE Enrichment Tab (NVD API) ──────────────────────────────────────────────
function CVEEnrichmentTab({ data, status }) {
  const [expanded, setExpanded] = useState(null);

  if (!data || status === "pending") return (
    <div className="empty-state">
      <div style={{ fontSize: "2rem", marginBottom: "0.5rem" }}>📋</div>
      <div style={{ fontWeight: 600, marginBottom: "0.25rem" }}>NVD CVE Lookup Pending</div>
      <div style={{ color: "var(--text-muted)", fontSize: "0.875rem" }}>Will query the NIST National Vulnerability Database for detected technologies.</div>
    </div>
  );
  if (status === "running") return (
    <div className="empty-state">
      <span className="spinner" style={{ width: 28, height: 28, marginBottom: "1rem" }} />
      <div style={{ fontWeight: 600 }}>Querying NVD CVE API for detected technologies...</div>
      <div style={{ color: "var(--text-muted)", fontSize: "12px", marginTop: "8px" }}>This may take 30–60s due to NVD rate limits.</div>
    </div>
  );

  const { cveFindings = [], findings = [], summary = {}, queriedKeywords = [] } = data;

  if (!summary.apiReachable && status === "complete") return (
    <div className="card" style={{ textAlign: "center", padding: "2.5rem" }}>
      <div style={{ fontSize: "2.5rem" }}>⚠️</div>
      <div style={{ fontWeight: 600, marginTop: "0.5rem" }}>NVD API Unreachable</div>
      <div style={{ color: "var(--text-muted)", fontSize: "0.875rem", marginTop: "0.25rem" }}>Could not connect to the NIST NVD API. Check network connectivity or set NVD_API_KEY in .env for higher rate limits.</div>
      <div style={{ color: "var(--text-muted)", fontSize: "11px", marginTop: "0.5rem" }}>Queried: {queriedKeywords.join(", ") || "none"}</div>
    </div>
  );

  const CVSS_COLOR = (score) => score >= 9 ? "#e11d48" : score >= 7 ? "#ea580c" : score >= 4 ? "#d97706" : "#16a34a";

  return (
    <div className="tab-sections">
      {/* Attribution notice */}
      <div style={{ padding: "8px 14px", background: "#0d1a2d", borderRadius: "8px", fontSize: "11px", color: "var(--text-muted)", borderLeft: "3px solid #3b82f6" }}>
        📢 This product uses data from the NVD API but is not endorsed or certified by the NVD. Data sourced from <a href="https://nvd.nist.gov" target="_blank" rel="noreferrer" style={{ color: "#60a5fa" }}>nvd.nist.gov</a>.
      </div>

      {/* Summary stats */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(5,1fr)", gap: "12px" }}>
        {[
          { label: "Total CVEs", value: summary.total, color: "#3b82f6" },
          { label: "Critical", value: summary.critical, color: "#e11d48" },
          { label: "High", value: summary.high, color: "#ea580c" },
          { label: "Medium", value: summary.medium, color: "#d97706" },
          { label: "Low", value: summary.low, color: "#16a34a" },
        ].map(s => (
          <div key={s.label} className="card" style={{ padding: "14px", textAlign: "center", borderTop: `3px solid ${s.color}` }}>
            <div style={{ fontSize: "1.8rem", fontWeight: 700, color: s.color }}>{s.value ?? 0}</div>
            <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "2px" }}>{s.label}</div>
          </div>
        ))}
      </div>

      {/* Queried technologies */}
      {queriedKeywords.length > 0 && (
        <div style={{ display: "flex", gap: "6px", flexWrap: "wrap", alignItems: "center" }}>
          <span style={{ fontSize: "12px", color: "var(--text-muted)" }}>Queried:</span>
          {queriedKeywords.map(k => (
            <span key={k} style={{ fontSize: "11px", background: "#1e2a40", padding: "3px 9px", borderRadius: "10px" }}>{k}</span>
          ))}
        </div>
      )}

      {/* CVE findings */}
      {cveFindings.length > 0 ? (
        <div className="card">
          <div className="card-header">🔴 CVE Findings from NVD ({cveFindings.length})</div>
          <div className="findings-list" style={{ padding: "8px" }}>
            {cveFindings.map(cve => (
              <div key={cve.cveId} className={`finding-card ${cve.severity} ${expanded === cve.cveId ? "expanded" : ""}`} onClick={() => setExpanded(expanded === cve.cveId ? null : cve.cveId)}>
                <div className="finding-card-header">
                  <SeverityBadge severity={cve.severity} />
                  <code style={{ fontSize: "12px", color: "#60a5fa", flexShrink: 0 }}>{cve.cveId}</code>
                  <span style={{ fontSize: "12px", background: `${CVSS_COLOR(cve.cvssScore)}20`, color: CVSS_COLOR(cve.cvssScore), padding: "1px 7px", borderRadius: "8px", flexShrink: 0 }}>CVSS {cve.cvssScore} v{cve.cvssVersion}</span>
                  <span className="finding-card-title" style={{ fontSize: "12px" }}>{cve.keyword}</span>
                  <span style={{ fontSize: "11px", color: "var(--text-muted)", flexShrink: 0 }}>📅 {cve.published}</span>
                  <span className="expand-icon">{expanded === cve.cveId ? "▲" : "▼"}</span>
                </div>
                {expanded === cve.cveId && (
                  <div className="finding-card-body">
                    <div className="finding-section"><div className="finding-section-label">Description</div>{cve.description}</div>
                    {cve.cvssVector && <div className="finding-section"><div className="finding-section-label">CVSS Vector</div><code style={{ fontSize: "11px" }}>{cve.cvssVector}</code></div>}
                    <div className="finding-section remediation">
                      <div className="finding-section-label">NVD Reference</div>
                      <a href={cve.nvdUrl} target="_blank" rel="noreferrer" style={{ color: "#60a5fa", fontSize: "12px" }}>{cve.nvdUrl}</a>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      ) : (
        status === "complete" && (
          <div className="card" style={{ textAlign: "center", padding: "2.5rem" }}>
            <div style={{ fontSize: "2.5rem" }}>✅</div>
            <div style={{ fontWeight: 600, marginTop: "0.5rem" }}>No CVEs Found for Detected Technologies</div>
            <div style={{ color: "var(--text-muted)", fontSize: "0.875rem", marginTop: "0.25rem" }}>Queried {queriedKeywords.length} technology keywords against the NVD API.</div>
          </div>
        )
      )}
    </div>
  );
}

// ── Retire.js Tab ─────────────────────────────────────────────────────────────
function RetireJsTab({ data, status }) {
  const [expanded, setExpanded] = useState(null);

  if (!data || status === "pending") return (
    <div className="empty-state">
      <div style={{ fontSize: "2rem", marginBottom: "0.5rem" }}>📦</div>
      <div style={{ fontWeight: 600, marginBottom: "0.25rem" }}>Retire.js Check Pending</div>
      <div style={{ color: "var(--text-muted)", fontSize: "0.875rem" }}>Will scan JavaScript libraries on target pages for known vulnerabilities.</div>
    </div>
  );
  if (status === "running") return (
    <div className="empty-state">
      <span className="spinner" style={{ width: 28, height: 28, marginBottom: "1rem" }} />
      <div style={{ fontWeight: 600 }}>Loading Retire.js database & scanning JS files...</div>
    </div>
  );

  const { libraryHits = [], findings = [], summary = {} } = data;

  return (
    <div className="tab-sections">
      {/* DB status */}
      <div style={{ padding: "8px 14px", background: "#0d1a2d", borderRadius: "8px", fontSize: "11px", color: "var(--text-muted)", borderLeft: `3px solid ${summary.dbLoaded ? "#22c55e" : "#e11d48"}` }}>
        {summary.dbLoaded ? "✅ Retire.js vulnerability database loaded successfully." : "⚠️ Retire.js database could not be loaded (network issue)."}
        {" "}Data sourced from <a href="https://github.com/RetireJS/retire.js" target="_blank" rel="noreferrer" style={{ color: "#60a5fa" }}>github.com/RetireJS/retire.js</a>.
      </div>

      {/* Summary */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(5,1fr)", gap: "12px" }}>
        {[
          { label: "Total Issues", value: summary.total, color: "#3b82f6" },
          { label: "Critical", value: summary.critical, color: "#e11d48" },
          { label: "High", value: summary.high, color: "#ea580c" },
          { label: "Medium", value: summary.medium, color: "#d97706" },
          { label: "Low", value: summary.low, color: "#16a34a" },
        ].map(s => (
          <div key={s.label} className="card" style={{ padding: "14px", textAlign: "center", borderTop: `3px solid ${s.color}` }}>
            <div style={{ fontSize: "1.8rem", fontWeight: 700, color: s.color }}>{s.value ?? 0}</div>
            <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "2px" }}>{s.label}</div>
          </div>
        ))}
      </div>

      {/* Vulnerable libraries */}
      {findings.length > 0 ? (
        <div className="card">
          <div className="card-header">📦 Vulnerable JavaScript Libraries ({findings.length})</div>
          <div className="findings-list" style={{ padding: "8px" }}>
            {[...findings].sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5)).map(f => (
              <div key={f.id} className={`finding-card ${f.severity} ${expanded === f.id ? "expanded" : ""}`} onClick={() => setExpanded(expanded === f.id ? null : f.id)}>
                <div className="finding-card-header">
                  <SeverityBadge severity={f.severity} />
                  <span className="finding-card-title">{f.title}</span>
                  {f.cves?.length > 0 && f.cves.slice(0, 2).map(cve => (
                    <code key={cve} style={{ fontSize: "10px", background: "#1e2a40", padding: "1px 6px", borderRadius: "6px", color: "#f87171" }}>{cve}</code>
                  ))}
                  <span className="expand-icon">{expanded === f.id ? "▲" : "▼"}</span>
                </div>
                {expanded === f.id && (
                  <div className="finding-card-body">
                    <div className="finding-section"><div className="finding-section-label">Library</div>{f.library} v{f.version}</div>
                    <div className="finding-section"><div className="finding-section-label">Description</div>{f.description}</div>
                    <div className="finding-section"><div className="finding-section-label">Affected URL</div><code style={{ wordBreak: "break-all", fontSize: "11px" }}>{f.affected}</code></div>
                    {f.cves?.length > 0 && <div className="finding-section"><div className="finding-section-label">CVE IDs</div>{f.cves.join(", ")}</div>}
                    {f.remediation && <div className="finding-section remediation"><div className="finding-section-label">Remediation</div>{f.remediation}</div>}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      ) : (
        status === "complete" && (
          <div className="card" style={{ textAlign: "center", padding: "2.5rem" }}>
            <div style={{ fontSize: "2.5rem" }}>✅</div>
            <div style={{ fontWeight: 600, marginTop: "0.5rem" }}>No Vulnerable JS Libraries Detected</div>
            <div style={{ color: "var(--text-muted)", fontSize: "0.875rem", marginTop: "0.25rem" }}>
              {libraryHits.length > 0 ? `${libraryHits.length} library version(s) identified — none had known vulnerabilities.` : "No identifiable JavaScript libraries found on page."}
            </div>
          </div>
        )
      )}
    </div>
  );
}

// ── API Discovery Tab ─────────────────────────────────────────────────────────
function APIDiscoveryTab({ data, status }) {
  const [activeSection, setActiveSection] = useState("overview");
  const [expandedSpec, setExpandedSpec] = useState(null);
  const [expandedGql, setExpandedGql] = useState(null);
  const [epFilter, setEpFilter] = useState("");

  if (!data || status === "pending") return (
    <div className="empty-state">
      <div style={{ fontSize: "2.5rem", marginBottom: "0.75rem" }}>🔗</div>
      <div style={{ fontWeight: 700, fontSize: "1.1rem", marginBottom: "0.4rem" }}>API Discovery Pending</div>
      <div style={{ color: "var(--text-muted)", fontSize: "0.875rem", maxWidth: 400, textAlign: "center" }}>
        Will enumerate public APIs via Swagger/OpenAPI, GraphQL, REST path probing, JS parsing, robots.txt and more.
      </div>
    </div>
  );

  if (status === "running") return (
    <div className="empty-state">
      <span className="spinner" style={{ width: 36, height: 36, marginBottom: "1rem" }} />
      <div style={{ fontWeight: 700, fontSize: "1.1rem" }}>Discovering Public APIs...</div>
      <div style={{ color: "var(--text-muted)", fontSize: "12px", marginTop: "8px" }}>
        Probing 60+ paths · Parsing JS files · Checking GraphQL · Scanning Swagger specs
      </div>
    </div>
  );

  const {
    openapi = [],
    graphql = [],
    rest = [],
    wsdl = [],
    wellKnown = [],
    jsEndpoints = [],
    robotsPaths = [],
    formActions = [],
    apiHeaders = [],
    summary = {},
  } = data;

  const SECTIONS = [
    { id: "overview", label: "📊 Overview", count: null },
    { id: "openapi", label: "📄 OpenAPI/Swagger", count: openapi.length },
    { id: "graphql", label: "⬡ GraphQL", count: graphql.length },
    { id: "rest", label: "🌐 REST Endpoints", count: rest.length },
    { id: "wsdl", label: "🔧 WSDL/SOAP", count: wsdl.length },
    { id: "jsapis", label: "📜 JS Extracted", count: jsEndpoints.length },
    { id: "other", label: "🗂 Other Sources", count: robotsPaths.length + formActions.length + apiHeaders.length },
  ];

  const STAT_CARDS = [
    { label: "OpenAPI Specs", value: summary.openApiSpecs ?? 0, color: "#6366f1", icon: "📄" },
    { label: "GraphQL Endpoints", value: summary.graphqlEndpoints ?? 0, color: "#ec4899", icon: "⬡" },
    { label: "REST Endpoints", value: summary.restEndpoints ?? 0, color: "#0ea5e9", icon: "🌐" },
    { label: "WSDL/SOAP", value: summary.wsdlEndpoints ?? 0, color: "#f59e0b", icon: "🔧" },
    { label: "JS-Extracted APIs", value: summary.jsExtractedEndpoints ?? 0, color: "#22c55e", icon: "📜" },
    { label: "Total Found", value: summary.total ?? 0, color: "#e11d48", icon: "🔗" },
  ];

  const filteredJs = epFilter
    ? jsEndpoints.filter(e => e.toLowerCase().includes(epFilter.toLowerCase()))
    : jsEndpoints;
  const filteredRest = epFilter
    ? rest.filter(r => r.path.toLowerCase().includes(epFilter.toLowerCase()))
    : rest;

  return (
    <div className="tab-sections">
      {/* Section nav pills */}
      <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
        {SECTIONS.map(s => (
          <button key={s.id} onClick={() => setActiveSection(s.id)}
            style={{
              padding: "5px 14px", borderRadius: "20px", border: `1px solid ${activeSection === s.id ? "#3b82f6" : "#1e2a40"}`,
              background: activeSection === s.id ? "#1a3050" : "transparent",
              cursor: "pointer", fontSize: "12px", fontWeight: 500,
              color: activeSection === s.id ? "#60a5fa" : "var(--text-muted)",
              display: "flex", alignItems: "center", gap: "6px",
            }}>
            {s.label}
            {s.count !== null && s.count > 0 && (
              <span style={{ background: "#3b82f620", color: "#60a5fa", borderRadius: "10px", padding: "0 7px", fontSize: "11px" }}>{s.count}</span>
            )}
          </button>
        ))}
      </div>

      {/* ── OVERVIEW ── */}
      {activeSection === "overview" && (
        <>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "12px" }}>
            {STAT_CARDS.map(s => (
              <div key={s.label} className="card" style={{ padding: "18px", textAlign: "center", borderTop: `3px solid ${s.color}`, cursor: "pointer" }}
                onClick={() => { const map = { "OpenAPI Specs": "openapi", "GraphQL Endpoints": "graphql", "REST Endpoints": "rest", "WSDL/SOAP": "wsdl", "JS-Extracted APIs": "jsapis" }; if (map[s.label]) setActiveSection(map[s.label]); }}>
                <div style={{ fontSize: "1.6rem", marginBottom: "4px" }}>{s.icon}</div>
                <div style={{ fontSize: "2rem", fontWeight: 800, color: s.color, lineHeight: 1 }}>{s.value}</div>
                <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "4px" }}>{s.label}</div>
              </div>
            ))}
          </div>

          {summary.total === 0 && jsEndpoints.length === 0 ? (
            <div className="card" style={{ textAlign: "center", padding: "2.5rem" }}>
              <div style={{ fontSize: "2.5rem" }}>✅</div>
              <div style={{ fontWeight: 600, marginTop: "0.5rem" }}>No Public APIs Discovered</div>
              <div style={{ color: "var(--text-muted)", fontSize: "0.875rem", marginTop: "0.25rem" }}>No Swagger specs, GraphQL, or REST API paths found via automated probing.</div>
            </div>
          ) : (
            <div className="card">
              <div className="card-header">🔗 Discovered API Sources</div>
              <div style={{ padding: "12px 16px", display: "flex", flexDirection: "column", gap: "10px" }}>
                {openapi.map(s => (
                  <div key={s.url} style={{ display: "flex", alignItems: "center", gap: "12px", padding: "10px", background: "#0d1a2d", borderRadius: "8px", borderLeft: "3px solid #6366f1" }}>
                    <span style={{ fontSize: "1.3rem" }}>📄</span>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontWeight: 600, fontSize: "13px" }}>{s.title}</div>
                      <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>OpenAPI {s.specVersion} · v{s.version} · {s.endpointCount} endpoints</div>
                    </div>
                    <code style={{ fontSize: "11px", color: "#6366f1" }}>{s.path}</code>
                  </div>
                ))}
                {graphql.map(g => (
                  <div key={g.url} style={{ display: "flex", alignItems: "center", gap: "12px", padding: "10px", background: "#0d1a2d", borderRadius: "8px", borderLeft: "3px solid #ec4899" }}>
                    <span style={{ fontSize: "1.3rem" }}>⬡</span>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontWeight: 600, fontSize: "13px" }}>GraphQL API</div>
                      <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>{g.introspection ? `✅ Introspection enabled · ${g.typeCount} types` : "⚠ Introspection disabled"}</div>
                    </div>
                    <code style={{ fontSize: "11px", color: "#ec4899" }}>{g.path}</code>
                  </div>
                ))}
                {rest.map(r => (
                  <div key={r.url} style={{ display: "flex", alignItems: "center", gap: "12px", padding: "10px", background: "#0d1a2d", borderRadius: "8px", borderLeft: "3px solid #0ea5e9" }}>
                    <span style={{ fontSize: "1.3rem" }}>🌐</span>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontWeight: 600, fontSize: "13px" }}>{r.path}</div>
                      <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>HTTP {r.httpStatus}{r.requiresAuth ? " · 🔒 Auth required" : " · 🔓 Public"}</div>
                    </div>
                    <span style={{ fontSize: "11px", padding: "2px 8px", borderRadius: "8px", background: r.requiresAuth ? "#d9780620" : "#0ea5e920", color: r.requiresAuth ? "#d97806" : "#0ea5e9" }}>{r.requiresAuth ? "Protected" : "Open"}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}

      {/* ── OPENAPI / SWAGGER ── */}
      {activeSection === "openapi" && (
        openapi.length === 0 ? (
          <div className="card" style={{ textAlign: "center", padding: "2.5rem" }}>
            <div style={{ fontSize: "2.5rem" }}>📄</div>
            <div style={{ fontWeight: 600, marginTop: "0.5rem" }}>No OpenAPI / Swagger Specs Found</div>
            <div style={{ color: "var(--text-muted)", fontSize: "0.875rem", marginTop: "0.25rem" }}>Probed {openapi.length === 0 ? "30+" : openapi.length} common spec paths.</div>
          </div>
        ) : openapi.map(spec => (
          <div key={spec.url} className="card" style={{ border: "1px solid #6366f140" }}>
            <div style={{ padding: "14px 16px", display: "flex", alignItems: "center", gap: "12px", cursor: "pointer", borderBottom: expandedSpec === spec.url ? "1px solid #1e2a40" : "none" }}
              onClick={() => setExpandedSpec(expandedSpec === spec.url ? null : spec.url)}>
              <span style={{ fontSize: "1.5rem" }}>📄</span>
              <div style={{ flex: 1 }}>
                <div style={{ fontWeight: 700, fontSize: "14px" }}>{spec.title}</div>
                <div style={{ fontSize: "12px", color: "var(--text-muted)", marginTop: "2px" }}>
                  OpenAPI {spec.specVersion} · API version {spec.version} · <a href={spec.url} target="_blank" rel="noreferrer" style={{ color: "#6366f1" }}>{spec.path}</a>
                </div>
              </div>
              <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                <span style={{ padding: "3px 10px", borderRadius: "10px", background: "#6366f120", color: "#6366f1", fontSize: "12px", fontWeight: 600 }}>{spec.endpointCount} endpoints</span>
                <span style={{ color: "var(--text-muted)", fontSize: "16px" }}>{expandedSpec === spec.url ? "▲" : "▼"}</span>
              </div>
            </div>
            {expandedSpec === spec.url && spec.endpoints.length > 0 && (
              <div style={{ padding: "12px 16px" }}>
                <div style={{ fontSize: "12px", color: "var(--text-muted)", marginBottom: "8px" }}>Documented Endpoints ({spec.endpoints.length})</div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                  {spec.endpoints.map(ep => (
                    <code key={ep} style={{ fontSize: "11px", background: "#131d30", padding: "3px 9px", borderRadius: "6px", color: "#a5b4fc", border: "1px solid #6366f130" }}>{ep}</code>
                  ))}
                </div>
              </div>
            )}
          </div>
        ))
      )}

      {/* ── GRAPHQL ── */}
      {activeSection === "graphql" && (
        graphql.length === 0 ? (
          <div className="card" style={{ textAlign: "center", padding: "2.5rem" }}>
            <div style={{ fontSize: "2.5rem" }}>⬡</div>
            <div style={{ fontWeight: 600, marginTop: "0.5rem" }}>No GraphQL Endpoints Found</div>
          </div>
        ) : graphql.map(gql => (
          <div key={gql.url} className="card" style={{ border: `1px solid ${gql.introspection ? "#ec489940" : "#1e2a40"}` }}>
            <div style={{ padding: "14px 16px", display: "flex", alignItems: "flex-start", gap: "12px", cursor: "pointer" }}
              onClick={() => setExpandedGql(expandedGql === gql.url ? null : gql.url)}>
              <span style={{ fontSize: "1.5rem", marginTop: "2px" }}>⬡</span>
              <div style={{ flex: 1 }}>
                <div style={{ fontWeight: 700, fontSize: "14px", marginBottom: "4px" }}>
                  GraphQL API — <a href={gql.url} target="_blank" rel="noreferrer" style={{ color: "#ec4899" }}>{gql.path}</a>
                </div>
                {gql.introspection ? (
                  <div style={{ padding: "8px 12px", background: "#e11d4810", borderRadius: "6px", fontSize: "12px", color: "#fca5a5", border: "1px solid #e11d4830" }}>
                    ⚠️ <strong>Introspection is ENABLED</strong> — The full schema is publicly accessible. An attacker can enumerate all types, queries, and mutations.
                  </div>
                ) : (
                  <div style={{ padding: "6px 12px", background: "#22c55e10", borderRadius: "6px", fontSize: "12px", color: "#86efac" }}>
                    ✅ Introspection is disabled.
                  </div>
                )}
                <div style={{ marginTop: "8px", display: "flex", gap: "10px", fontSize: "12px", color: "var(--text-muted)" }}>
                  <span>Query type: <code style={{ color: "#a5b4fc" }}>{gql.queryType}</code></span>
                  {gql.mutationType && <span>Mutation type: <code style={{ color: "#a5b4fc" }}>{gql.mutationType}</code></span>}
                  <span>{gql.typeCount} types discovered</span>
                </div>
              </div>
              <span style={{ color: "var(--text-muted)", fontSize: "16px" }}>{expandedGql === gql.url ? "▲" : "▼"}</span>
            </div>
            {expandedGql === gql.url && gql.types.length > 0 && (
              <div style={{ padding: "12px 16px", borderTop: "1px solid #1e2a40" }}>
                <div style={{ fontSize: "12px", color: "var(--text-muted)", marginBottom: "8px" }}>Schema Types</div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                  {gql.types.map(t => (
                    <span key={t} style={{ fontSize: "11px", background: "#131d30", padding: "3px 9px", borderRadius: "6px", color: "#f9a8d4", border: "1px solid #ec489930" }}>{t}</span>
                  ))}
                </div>
              </div>
            )}
          </div>
        ))
      )}

      {/* ── REST ENDPOINTS ── */}
      {activeSection === "rest" && (
        <>
          <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
            <input
              style={{ flex: 1, padding: "7px 12px", background: "#0d1a2d", border: "1px solid #1e2a40", borderRadius: "8px", color: "#c8d0e0", fontSize: "13px" }}
              placeholder="Filter endpoints..."
              value={epFilter}
              onChange={e => setEpFilter(e.target.value)}
            />
            <span style={{ fontSize: "12px", color: "var(--text-muted)", whiteSpace: "nowrap" }}>{filteredRest.length} endpoint{filteredRest.length !== 1 ? "s" : ""}</span>
          </div>
          {filteredRest.length === 0 ? (
            <div className="card" style={{ textAlign: "center", padding: "2.5rem" }}>
              <div style={{ fontSize: "2.5rem" }}>🌐</div>
              <div style={{ fontWeight: 600, marginTop: "0.5rem" }}>No REST Endpoints Found</div>
            </div>
          ) : (
            <div className="card">
              <div className="card-header">🌐 REST API Endpoints ({filteredRest.length})</div>
              <table className="data-table">
                <thead><tr><th>Path</th><th>HTTP Status</th><th>Access</th><th>Content-Type</th><th>Keys Detected</th></tr></thead>
                <tbody>
                  {filteredRest.map((r, i) => (
                    <tr key={i}>
                      <td><a href={r.url} target="_blank" rel="noreferrer" style={{ color: "#60a5fa", fontFamily: "monospace", fontSize: "12px" }}>{r.path}</a></td>
                      <td><span style={{ padding: "2px 8px", borderRadius: "8px", fontSize: "11px", fontWeight: 600, background: r.httpStatus < 300 ? "#22c55e20" : "#d9780620", color: r.httpStatus < 300 ? "#22c55e" : "#d97806" }}>{r.httpStatus}</span></td>
                      <td>
                        <span style={{ padding: "2px 8px", borderRadius: "8px", fontSize: "11px", background: r.requiresAuth ? "#d9780615" : "#0ea5e915", color: r.requiresAuth ? "#d97806" : "#0ea5e9" }}>
                          {r.requiresAuth ? "🔒 Auth" : "🔓 Open"}
                        </span>
                      </td>
                      <td style={{ fontSize: "11px", color: "var(--text-muted)" }}>{(r.contentType || "").split(";")[0]}</td>
                      <td>
                        {r.responseKeys?.length > 0 ? (
                          <div style={{ display: "flex", flexWrap: "wrap", gap: "3px" }}>
                            {r.responseKeys.slice(0, 4).map(k => <code key={k} style={{ fontSize: "10px", background: "#131d30", padding: "1px 6px", borderRadius: "4px", color: "#94a3b8" }}>{k}</code>)}
                            {r.responseKeys.length > 4 && <span style={{ fontSize: "10px", color: "var(--text-muted)" }}>+{r.responseKeys.length - 4}</span>}
                          </div>
                        ) : <span style={{ color: "var(--text-muted)", fontSize: "11px" }}>—</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}

      {/* ── WSDL / SOAP ── */}
      {activeSection === "wsdl" && (
        wsdl.length === 0 ? (
          <div className="card" style={{ textAlign: "center", padding: "2.5rem" }}>
            <div style={{ fontSize: "2.5rem" }}>🔧</div>
            <div style={{ fontWeight: 600, marginTop: "0.5rem" }}>No WSDL / SOAP Endpoints Found</div>
          </div>
        ) : wsdl.map((w, i) => (
          <div key={i} className="card" style={{ border: "1px solid #f59e0b40" }}>
            <div style={{ padding: "14px 16px", display: "flex", gap: "12px" }}>
              <span style={{ fontSize: "1.5rem" }}>🔧</span>
              <div>
                <div style={{ fontWeight: 700 }}>SOAP/WSDL Service</div>
                <a href={w.url} target="_blank" rel="noreferrer" style={{ color: "#f59e0b", fontSize: "12px" }}>{w.url}</a>
                {w.services.length > 0 && (
                  <div style={{ marginTop: "8px", display: "flex", gap: "6px", flexWrap: "wrap" }}>
                    {w.services.map(s => <span key={s} style={{ fontSize: "11px", background: "#f59e0b20", color: "#fbbf24", padding: "2px 8px", borderRadius: "8px" }}>{s}</span>)}
                  </div>
                )}
              </div>
            </div>
          </div>
        ))
      )}

      {/* ── JS EXTRACTED ENDPOINTS ── */}
      {activeSection === "jsapis" && (
        <>
          <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
            <input
              style={{ flex: 1, padding: "7px 12px", background: "#0d1a2d", border: "1px solid #1e2a40", borderRadius: "8px", color: "#c8d0e0", fontSize: "13px" }}
              placeholder="Filter extracted endpoints..."
              value={epFilter}
              onChange={e => setEpFilter(e.target.value)}
            />
            <span style={{ fontSize: "12px", color: "var(--text-muted)", whiteSpace: "nowrap" }}>{filteredJs.length} endpoint{filteredJs.length !== 1 ? "s" : ""}</span>
          </div>
          {filteredJs.length === 0 ? (
            <div className="card" style={{ textAlign: "center", padding: "2.5rem" }}>
              <div style={{ fontSize: "2.5rem" }}>📜</div>
              <div style={{ fontWeight: 600, marginTop: "0.5rem" }}>No Endpoints Extracted from JavaScript</div>
              <div style={{ color: "var(--text-muted)", fontSize: "0.875rem", marginTop: "0.25rem" }}>No API URLs found in fetch(), axios(), or XHR calls in page scripts.</div>
            </div>
          ) : (
            <div className="card">
              <div className="card-header" style={{ display: "flex", justifyContent: "space-between" }}>
                <span>📜 Endpoints Extracted from JavaScript ({filteredJs.length})</span>
                <span style={{ fontSize: "11px", color: "var(--text-muted)", fontWeight: 400 }}>Extracted from fetch/axios/XHR calls</span>
              </div>
              <div style={{ padding: "12px", display: "flex", flexWrap: "wrap", gap: "6px" }}>
                {filteredJs.map((ep, i) => (
                  <code key={i} style={{ fontSize: "11px", background: "#0d1a2d", border: "1px solid #22c55e30", color: "#86efac", padding: "4px 10px", borderRadius: "6px", cursor: "pointer", wordBreak: "break-all" }}
                    onClick={() => { try { const url = ep.startsWith("/") ? `https://${data.domain}${ep}` : ep; window.open(url, "_blank"); } catch (_) { } }}>
                    {ep}
                  </code>
                ))}
              </div>
            </div>
          )}
        </>
      )}

      {/* ── OTHER SOURCES (robots.txt, forms, headers) ── */}
      {activeSection === "other" && (
        <>
          {robotsPaths.length > 0 && (
            <div className="card">
              <div className="card-header">🤖 API Paths from robots.txt / sitemap</div>
              <table className="data-table">
                <thead><tr><th>Source</th><th>Path</th></tr></thead>
                <tbody>
                  {robotsPaths.map((r, i) => (
                    <tr key={i}>
                      <td><span style={{ fontSize: "11px", background: "#1e2a40", padding: "2px 8px", borderRadius: "6px" }}>{r.source}</span></td>
                      <td><code style={{ fontSize: "12px", color: "#60a5fa" }}>{r.path}</code></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {formActions.length > 0 && (
            <div className="card">
              <div className="card-header">📝 Form Action URLs</div>
              <div style={{ padding: "12px", display: "flex", flexWrap: "wrap", gap: "6px" }}>
                {formActions.map((fa, i) => <code key={i} style={{ fontSize: "11px", background: "#0d1a2d", border: "1px solid #1e2a40", color: "#94a3b8", padding: "4px 10px", borderRadius: "6px" }}>{fa}</code>)}
              </div>
            </div>
          )}

          {apiHeaders.length > 0 && (
            <div className="card">
              <div className="card-header">📡 API-Related Response Headers</div>
              <table className="data-table">
                <thead><tr><th>Header</th><th>Value</th></tr></thead>
                <tbody>
                  {apiHeaders.map((h, i) => (
                    <tr key={i}>
                      <td><code style={{ fontSize: "11px", color: "#60a5fa" }}>{h.header}</code></td>
                      <td style={{ fontSize: "12px", color: "var(--text-muted)", wordBreak: "break-all" }}>{h.value || h.url || h.rel}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {robotsPaths.length === 0 && formActions.length === 0 && apiHeaders.length === 0 && (
            <div className="card" style={{ textAlign: "center", padding: "2.5rem" }}>
              <div style={{ fontSize: "2.5rem" }}>🗂</div>
              <div style={{ fontWeight: 600, marginTop: "0.5rem" }}>No Additional API Signals Found</div>
              <div style={{ color: "var(--text-muted)", fontSize: "0.875rem", marginTop: "0.25rem" }}>robots.txt, sitemaps, form actions, and response headers yielded no API clues.</div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ── Alerts View ───────────────────────────────────────────────────────────────
function AlertsView({ alertHistory, onMarkRead, onMarkAllRead }) {
  const triggerIcon = { severity: "🚨", risk_score: "📊", scan_complete: "✅", attack_type: "⚔", open_port: "🔌", test: "🧪" };
  const sevColor = { critical: "#e11d48", high: "#ea580c", medium: "#d97706", low: "#16a34a" };
  return (
    <div className="view-content">
      <div className="page-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div><h1>🚨 Alerts</h1><p className="page-sub">Fired notifications from your alert rules</p></div>
        {alertHistory.some(a => !a.read) && (
          <button className="scan-btn" style={{ padding: "8px 16px", fontSize: "12px" }} onClick={onMarkAllRead}>Mark All Read</button>
        )}
      </div>
      {alertHistory.length === 0 ? (
        <div className="empty-state" style={{ padding: "60px" }}>
          <div style={{ fontSize: "3rem" }}>🔕</div>
          <div style={{ fontWeight: 600, marginTop: "1rem" }}>No Alerts Yet</div>
          <div style={{ color: "var(--text-muted)", marginTop: "0.5rem" }}>Configure rules in Alert Settings. Alerts fire when a scan matches your conditions.</div>
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
          {alertHistory.map(a => (
            <div key={a.id} className={`card alert-item ${a.read ? "read" : "unread"}`} onClick={() => !a.read && onMarkRead(a.id)} style={{ cursor: a.read ? "default" : "pointer" }}>
              <div style={{ display: "flex", gap: "12px", padding: "14px 16px", alignItems: "flex-start" }}>
                <span style={{ fontSize: "1.5rem", flexShrink: 0 }}>{triggerIcon[a.trigger] || "🔔"}</span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "4px" }}>
                    <span style={{ fontWeight: 600, fontSize: "14px" }}>{a.ruleName}</span>
                    {!a.read && <span style={{ width: 8, height: 8, borderRadius: "50%", background: "#3b82f6", display: "inline-block" }} />}
                    <span style={{ fontSize: "11px", color: "var(--text-muted)", marginLeft: "auto" }}>{new Date(a.timestamp).toLocaleString()}</span>
                  </div>
                  <div style={{ fontSize: "13px" }}><code style={{ color: "#60a5fa" }}>{a.domain}</code>{" — "}{a.triggerDetail}</div>
                  {a.finding && <div style={{ fontSize: "12px", color: "var(--text-muted)", marginTop: "4px" }}>Finding: <span style={{ color: sevColor[a.finding.severity] || "#c8d0e0" }}>{a.finding.title}</span></div>}
                  <div style={{ display: "flex", gap: "6px", marginTop: "6px", flexWrap: "wrap" }}>
                    <span style={{ fontSize: "11px", background: "#1e2a40", padding: "2px 8px", borderRadius: "10px" }}>Risk: {a.riskScore} — {a.riskGrade}</span>
                    {(a.channels || []).map(ch => <span key={ch} style={{ fontSize: "11px", background: "#1e2a40", padding: "2px 8px", borderRadius: "10px" }}>{ch}</span>)}
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Alert Settings View ───────────────────────────────────────────────────────
function AlertSettingsView() {
  const [rules, setRules] = useState([]);
  const [config, setConfig] = useState({ url: "", slack: "", discord: "", email: { host: "", port: 587, user: "", pass: "", to: "" } });
  const [saved, setSaved] = useState(false);
  const [notifPerm, setNotifPerm] = useState(typeof Notification !== "undefined" ? Notification.permission : "default");
  useEffect(() => {
    fetch(`${API_BASE}/alerts/rules`).then(r => r.json()).then(setRules).catch(() => { });
    fetch(`${API_BASE}/alerts/config`).then(r => r.json()).then(setConfig).catch(() => { });
  }, []);
  const saveConfig = async () => {
    await fetch(`${API_BASE}/alerts/config`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(config) });
    setSaved(true); setTimeout(() => setSaved(false), 2500); showToast("Alert config saved!", "success");
  };
  const toggleRule = async (rule) => {
    const updated = { ...rule, enabled: !rule.enabled };
    await fetch(`${API_BASE}/alerts/rules/${rule.id}`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(updated) });
    setRules(p => p.map(r => r.id === rule.id ? updated : r));
  };
  const toggleChannel = async (rule, channel) => {
    const channels = rule.channels.includes(channel) ? rule.channels.filter(c => c !== channel) : [...rule.channels, channel];
    const updated = { ...rule, channels };
    await fetch(`${API_BASE}/alerts/rules/${rule.id}`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(updated) });
    setRules(p => p.map(r => r.id === rule.id ? updated : r));
  };
  const sendTest = async () => { await fetch(`${API_BASE}/alerts/test`, { method: "POST" }); showToast("🧪 Test alert fired!", "warning", 4000); };
  const requestNotif = async () => { const p = await Notification.requestPermission(); setNotifPerm(p); if (p === "granted") showToast("✅ Browser notifications enabled!", "success"); };
  const CHANNELS = ["browser", "webhook", "slack", "discord", "email"];
  const CH_ICONS = { browser: "🔔", webhook: "🌐", slack: "💬", discord: "🎮", email: "📧" };
  return (
    <div className="view-content">
      <div className="page-header"><h1>⚙ Alert Settings</h1><p className="page-sub">Configure alert rules and notification channels</p></div>
      <div className="card" style={{ borderLeft: notifPerm === "granted" ? "4px solid #22c55e" : "4px solid #d97706" }}>
        <div style={{ padding: "16px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div>
            <div style={{ fontWeight: 600, marginBottom: "2px" }}>🔔 Browser Notifications</div>
            <div style={{ fontSize: "12px", color: "var(--text-muted)" }}>Status: <strong style={{ color: notifPerm === "granted" ? "#22c55e" : "#d97706" }}>{notifPerm}</strong></div>
          </div>
          {notifPerm !== "granted" && <button className="scan-btn" style={{ padding: "8px 14px", fontSize: "12px" }} onClick={requestNotif}>Enable</button>}
        </div>
      </div>
      <div className="card">
        <div className="card-header">🛡 Alert Rules</div>
        {rules.map(rule => (
          <div key={rule.id} style={{ padding: "14px 16px", borderBottom: "1px solid #0f1825", display: "flex", alignItems: "center", gap: "14px" }}>
            <label className="toggle-switch" title={rule.enabled ? "Disable" : "Enable"}>
              <input type="checkbox" checked={rule.enabled} onChange={() => toggleRule(rule)} />
              <span className="toggle-slider" />
            </label>
            <div style={{ flex: 1 }}>
              <div style={{ fontWeight: 500, fontSize: "14px", marginBottom: "6px", color: rule.enabled ? "#c8d0e0" : "#5a6a80" }}>{rule.name}</div>
              <div style={{ display: "flex", gap: "6px" }}>
                {CHANNELS.map(ch => (
                  <button key={ch} onClick={() => toggleChannel(rule, ch)}
                    style={{ fontSize: "14px", background: rule.channels.includes(ch) ? "#1a3050" : "#131d30", border: `1px solid ${rule.channels.includes(ch) ? "#3b82f6" : "#1e2a40"}`, borderRadius: "6px", padding: "3px 8px", cursor: "pointer", transition: "all 0.15s" }}
                    title={ch}>{CH_ICONS[ch]}</button>
                ))}
              </div>
            </div>
          </div>
        ))}
      </div>
      <div className="card">
        <div className="card-header">🌐 Channel Configuration</div>
        <div style={{ padding: "16px", display: "flex", flexDirection: "column", gap: "12px" }}>
          {[{ key: "url", label: "🌐 Webhook URL", ph: "https://your-webhook.com/hook" }, { key: "slack", label: "💬 Slack Webhook", ph: "https://hooks.slack.com/services/..." }, { key: "discord", label: "🎮 Discord Webhook", ph: "https://discord.com/api/webhooks/..." }]
            .map(({ key, label, ph }) => (
              <div key={key}>
                <label style={{ fontSize: "12px", color: "var(--text-muted)", display: "block", marginBottom: "4px" }}>{label}</label>
                <input className="scan-input" style={{ width: "100%" }} value={config[key] || ""} onChange={e => setConfig(p => ({ ...p, [key]: e.target.value }))} placeholder={ph} />
              </div>
            ))}
          <div style={{ borderTop: "1px solid #1e2a40", paddingTop: "12px" }}>
            <div style={{ fontSize: "12px", color: "var(--text-muted)", marginBottom: "8px" }}>📧 Email (optional — requires npm install nodemailer in backend)</div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 80px", gap: "8px", marginBottom: "8px" }}>
              <input className="scan-input" placeholder="SMTP Host" value={config.email?.host || ""} onChange={e => setConfig(p => ({ ...p, email: { ...p.email, host: e.target.value } }))} />
              <input className="scan-input" placeholder="Port" type="number" value={config.email?.port || 587} onChange={e => setConfig(p => ({ ...p, email: { ...p.email, port: e.target.value } }))} />
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px", marginBottom: "8px" }}>
              <input className="scan-input" placeholder="SMTP User" value={config.email?.user || ""} onChange={e => setConfig(p => ({ ...p, email: { ...p.email, user: e.target.value } }))} />
              <input className="scan-input" placeholder="Password" type="password" value={config.email?.pass || ""} onChange={e => setConfig(p => ({ ...p, email: { ...p.email, pass: e.target.value } }))} />
            </div>
            <input className="scan-input" style={{ width: "100%" }} placeholder="Recipient email" value={config.email?.to || ""} onChange={e => setConfig(p => ({ ...p, email: { ...p.email, to: e.target.value } }))} />
          </div>
          <div style={{ display: "flex", gap: "10px" }}>
            <button className="scan-btn" onClick={saveConfig}>{saved ? "✅ Saved!" : "💾 Save Config"}</button>
            <button className="scan-btn" style={{ background: "#1e2a40" }} onClick={sendTest}>🧪 Send Test Alert</button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Search Modal ──────────────────────────────────────────────────────────────
function SearchModal({ scans, onClose, onSelectScan }) {
  const [q, setQ] = useState("");
  const [sev, setSev] = useState("all");
  const inputRef = useRef(null);
  useEffect(() => { inputRef.current?.focus(); }, []);
  const results = [];
  for (const scan of scans.filter(s => s.findings?.length)) {
    for (const f of scan.findings) {
      if (sev !== "all" && f.severity !== sev) continue;
      const ss = `${f.title} ${f.description || ""} ${scan.domain}`.toLowerCase();
      if (q && !ss.includes(q.toLowerCase())) continue;
      results.push({ scan, finding: f });
      if (results.length >= 50) break;
    }
    if (results.length >= 50) break;
  }
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-box" onClick={e => e.stopPropagation()}>
        <div style={{ padding: "16px", borderBottom: "1px solid #1e2a40" }}>
          <input ref={inputRef} className="scan-input" style={{ width: "100%", fontSize: "15px" }} value={q} onChange={e => setQ(e.target.value)} placeholder="Search findings across all scans..." />
          <div style={{ display: "flex", gap: "6px", marginTop: "10px", alignItems: "center" }}>
            {["all", "critical", "high", "medium", "low"].map(s => (
              <button key={s} className={`filter-btn ${sev === s ? `active ${s}` : ""}`} onClick={() => setSev(s)}>{s.charAt(0).toUpperCase() + s.slice(1)}</button>
            ))}
            <span style={{ marginLeft: "auto", fontSize: "11px", color: "var(--text-muted)" }}>{results.length} result{results.length !== 1 ? "s" : ""}</span>
          </div>
        </div>
        <div style={{ maxHeight: "380px", overflowY: "auto" }}>
          {results.length === 0 ? (
            <div style={{ padding: "40px", textAlign: "center", color: "var(--text-muted)" }}>{q ? "No findings match your search" : "Type to search across all scan findings..."}</div>
          ) : results.map(({ scan, finding }, i) => (
            <div key={i} className="search-result" onClick={() => onSelectScan(scan.id)}>
              <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "4px" }}>
                <SeverityBadge severity={finding.severity} />
                <span style={{ fontSize: "13px", fontWeight: 500, flex: 1 }}>{finding.title}</span>
              </div>
              <div style={{ fontSize: "11px", color: "var(--text-muted)" }}><code style={{ color: "#60a5fa" }}>{scan.domain}</code> · {finding.module}</div>
            </div>
          ))}
        </div>
        <div style={{ padding: "10px 16px", borderTop: "1px solid #1e2a40", fontSize: "11px", color: "var(--text-muted)", display: "flex", gap: "16px" }}>
          <span><kbd style={{ background: "#1e2a40", padding: "1px 5px", borderRadius: "3px" }}>↵</kbd> Open scan</span>
          <span><kbd style={{ background: "#1e2a40", padding: "1px 5px", borderRadius: "3px" }}>Esc</kbd> Close</span>
        </div>
      </div>
    </div>
  );
}

// ── Shortcuts Modal ───────────────────────────────────────────────────────────
function ShortcutsModal({ onClose }) {
  const shortcuts = [
    { keys: "Ctrl+K", action: "Open global search" },
    { keys: "Ctrl+N", action: "New scan / focus domain input" },
    { keys: "Ctrl+H", action: "Go to Scan History" },
    { keys: "Ctrl+D", action: "Go to Dashboard" },
    { keys: "?", action: "Show keyboard shortcuts" },
    { keys: "Esc", action: "Close modal" },
  ];
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-box" style={{ maxWidth: "400px" }} onClick={e => e.stopPropagation()}>
        <div style={{ padding: "16px 20px", borderBottom: "1px solid #1e2a40", fontWeight: 700, fontSize: "15px" }}>⌨ Keyboard Shortcuts</div>
        {shortcuts.map(s => (
          <div key={s.keys} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 20px", borderBottom: "1px solid #0a1020", fontSize: "13px" }}>
            <span style={{ color: "var(--text-muted)" }}>{s.action}</span>
            <kbd style={{ background: "#1e2a40", padding: "2px 8px", borderRadius: "4px", fontSize: "11px", fontFamily: "monospace", flexShrink: 0 }}>{s.keys}</kbd>
          </div>
        ))}
        <div style={{ padding: "12px 20px" }}>
          <button className="scan-btn" style={{ width: "100%", justifyContent: "center" }} onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
}

