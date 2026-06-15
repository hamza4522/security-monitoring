# 🛡️ ReconScan — Agentless Security Assessment Platform

A modular, full-stack external security reconnaissance and vulnerability assessment platform.  
**No agents. No Nessus license. No API keys required.**

Built with **React + Node.js** · Styled with a **Datadog-inspired dark theme** · Real-time via **WebSockets**

---

## ✨ Features

| Capability | Description |
|---|---|
| 🌐 **Asset Discovery** | Subdomain enum, live host probing, CDN/WAF detection |
| 🔒 **SSL/TLS Scan** | Certificate validity, expiry, weak ciphers, HSTS analysis |
| 🗂️ **DNS Assessment** | SPF, DMARC, DKIM, DNSSEC, AXFR zone transfer test |
| 🔭 **Port Scanning** | Top ports via TCP sockets + nmap fallback |
| 🧬 **Service Fingerprint** | Banner grabbing, version detection, security header audit |
| 🧠 **Web Tech Fingerprint** | Wappalyzer-style: CMS, frameworks, CDN, libraries |
| 🛡️ **WAF / CDN Detection** | Cloudflare, Akamai, Imperva, Fastly, and 20+ more |
| ⚔️ **Active Web Attacks** | XSS, SQLi, CMDi, LFI/RFI — real probes via Wapiti-style engine |
| 🔬 **Nessus-Style Scanner** | 50+ agentless plugin checks across 11 families, CVSS scores, CVE links |
| 🏛️ **CMS Vulnerability Scan** | WordPress, Drupal, Joomla, Magento plugin/version CVEs |
| 🔗 **Public API Discovery** | OpenAPI, GraphQL, REST, WSDL, JS-extracted endpoints |
| 📜 **JS Secret Scanner** | AWS keys, JWTs, private keys, API tokens in page scripts |
| 🔁 **Subdomain Takeover** | Detects dangling CNAME records across 30+ cloud services |
| 💊 **Retire.js Checker** | Vulnerable JavaScript libraries via Retire.js database |
| 📡 **NVD CVE Enrichment** | Version-aware CVE lookup against NIST NVD API |
| 🎯 **Scan Mode Toggle** | **Full Scan** (all subdomains) or **Single Domain** (fast, focused) |

---

## 🏗️ Architecture

```
recon-platform/
├── backend/
│   ├── server.js                   # Express + WebSocket server
│   ├── routes/
│   │   ├── scan.js                 # Scan orchestration pipeline
│   │   └── report.js               # PDF/MD/JSON report generation
│   ├── modules/
│   │   ├── assetDiscovery.js       # Subdomain enum, live hosts, CDN
│   │   ├── sslScan.js              # TLS certificate & cipher checks
│   │   ├── dnsAssessment.js        # SPF, DMARC, DKIM, AXFR
│   │   ├── portScan.js             # TCP port scanning
│   │   ├── serviceFingerprint.js   # Banner grab, header audit
│   │   ├── webTechFingerprint.js   # Wappalyzer-style detection
│   │   ├── wafDetector.js          # WAF/CDN fingerprinting
│   │   ├── vulnAssessment.js       # Core vulnerability checks
│   │   ├── nucleiChecks.js         # Nuclei-style template checks
│   │   ├── jsSecretScanner.js      # Secrets in JavaScript files
│   │   ├── subdomainTakeover.js    # Dangling CNAME detection
│   │   ├── wapitiscan.js           # Active web attack probing
│   │   ├── cmsVulnScan.js          # CMS-specific CVE checks
│   │   ├── cveEnrichment.js        # NVD CVE enrichment
│   │   ├── retireJsChecker.js      # Retire.js vulnerable libs
│   │   ├── apiDiscovery.js         # Public API enumeration
│   │   └── nessusScanner.js        # Agentless Nessus-style scanner
│   └── utils/
│       ├── exec.js                 # CLI tool runner with timeout
│       ├── riskScoring.js          # 0–100 risk score + grade
│       └── alertEngine.js          # Webhook/Slack/Discord alerts
└── frontend/
    └── src/
        ├── App.jsx                 # Full React UI — all tabs & views
        ├── App.css                 # Layout, animations, components
        └── theme.css               # Datadog-style color variables
```

---

## 🚀 Quick Start

### Option A: Direct (Dev Mode)

```bash
cd recon-platform
chmod +x setup.sh && ./setup.sh
```

### Option B: Manual

```bash
# Terminal 1 — Backend (port 3001)
cd recon-platform/backend
npm install
node server.js

# Terminal 2 — Frontend (port 3000)
cd recon-platform/frontend
npm install
npm start
```

Open **http://localhost:3000**

### Option C: Docker

```bash
cd recon-platform
docker-compose up --build
```

---

## 🔬 Nessus-Style Scanner (No License Required)

The built-in `nessusScanner` module performs **50+ vulnerability checks** across **11 plugin families** — entirely agentless, no Nessus install or API key needed:

| Plugin Family | Checks |
|---|---|
| **Web Servers** | Server version CVEs (Apache, Nginx, IIS), TRACE/PUT methods |
| **TLS/SSL** | TLSv1.0, expired/self-signed certs, HSTS strength, weak keys |
| **Authentication** | HTTP Basic over HTTP, anonymous FTP, admin panel exposure, default creds |
| **Information Disclosure** | `.git`, `.env`, phpinfo, Actuator, heap dumps, SQL backups |
| **Injection** | SQL error reflection, reflected XSS, path traversal |
| **Network Services** | SMB, RDP, VNC, Redis, Elasticsearch, MongoDB, Docker API, WebLogic |
| **CGI** | Shellshock (CVE-2014-6271), Heartbleed cert date hint |
| **Security Policy** | CSP, X-Frame-Options, XCTO, Referrer-Policy, Permissions-Policy |
| **CORS & Cookies** | Wildcard CORS, origin reflection, Secure/HttpOnly/SameSite flags |
| **DNS** | Zone transfer (AXFR), SPF, DMARC |
| **FTP** | Open FTP service, anonymous login |

---

## 🎯 Scan Modes

| Mode | What Gets Scanned | Speed |
|---|---|---|
| 🌐 **Full Scan** | Primary domain + all discovered subdomains | ~2–8 min |
| 🎯 **Single Domain** | Primary domain only — no subdomain expansion | ~45–90 sec |

---

## 🛠️ Security Tools (Optional — Fallback Works Without Them)

| Tool | Source | Purpose |
|---|---|---|
| `subfinder` | ProjectDiscovery | Subdomain enumeration |
| `httpx` | ProjectDiscovery | Live host probing |
| `dnsx` | ProjectDiscovery | Bulk DNS resolution |
| `nmap` | Nmap.org | Port scanning + service detection |

Install Go tools:
```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
```

> Without these tools installed, the platform falls back to pure Node.js — DNS enumeration via wordlist, HTTP probing via `fetch`, TCP socket scanning.

---

## 📡 API Reference

```
POST   /api/scan/start            Start scan { domain, scanMode: 'full'|'single' }
GET    /api/scan                  List all scans
GET    /api/scan/:id              Get scan status + full results
DELETE /api/scan/:id              Cancel a running scan
GET    /api/scan/compare?a=&b=    Compare two scans

GET    /api/report/:id/pdf        Download PDF report
GET    /api/report/:id/markdown   Download Markdown report
GET    /api/report/:id/download   Download full JSON report

WS     ws://localhost:3001?scanId=<id>   Real-time scan progress
```

---

## 📊 Risk Scoring

Findings are aggregated into a **0–100 risk score** with letter grade:

| Grade | Score | Label |
|---|---|---|
| A+ / A | 0–20 | Low risk |
| B | 21–30 | Moderate |
| C | 31–45 | Elevated |
| D | 46–60 | High risk |
| E | 61–75 | Critical |
| F | 76–100 | Severe |

---

## 🎨 Theming

The UI uses a **Datadog-inspired dark theme** with full CSS variable support. To customize colors, edit:

```
frontend/src/theme.css
```

All changes hot-reload instantly in the browser. The file contains:
- Background shades (`--bg-main`, `--bg-card`)
- Datadog purple primary accent (`--accent-blue: #7b4fff`)
- Datadog orange for warnings (`--accent-orange: #ff6b2b`)
- Status colors, border opacities, and glass effects

---

## ⌨️ Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl+K` | Global finding search |
| `Ctrl+N` | New scan / focus domain input |
| `Ctrl+H` | Go to Scan History |
| `Ctrl+D` | Go to Dashboard |
| `?` | Show shortcuts modal |
| `Esc` | Close modal |

---

## 🧩 Adding New Modules

1. Create `backend/modules/yourModule.js` — export `async function runYourModule(domain, onProgress)`
2. Return `{ findings: [], ...data }` — findings: `{ id, severity, title, description, module, remediation }`
3. Register in `routes/scan.js` `moduleList` array with `key`, `label`, `weight`, `runner`
4. Add a tab component in `frontend/src/App.jsx`

---

## ⚠️ Responsible Use

This tool is intended for **authorized security assessments only**.  
Always obtain **explicit written permission** before scanning any domain you do not own.  
Unauthorized scanning may violate the Computer Fraud and Abuse Act (CFAA) and similar laws in your jurisdiction.
