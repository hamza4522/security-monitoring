# ReconScan — Agentless Security Assessment Platform

A modular, full-stack external security reconnaissance platform. No agents or software installed on the target. Built with React + Node.js. Uses ProjectDiscovery CLI tools (subfinder, httpx, dnsx) + nmap.

---

## Architecture

```
recon-platform/
├── backend/
│   ├── server.js              # Express + WebSocket API
│   ├── routes/
│   │   ├── scan.js            # Scan orchestration & pipeline
│   │   └── report.js          # Report generation endpoints
│   ├── modules/
│   │   ├── assetDiscovery.js  # Module 1: Subdomain enum, live hosts, CDN/WAF
│   │   ├── dnsAssessment.js   # Module 2: SPF, DMARC, DKIM, DNSSEC, zone xfer
│   │   ├── portScan.js        # Module 3: nmap / TCP socket port scanning
│   │   ├── serviceFingerprint.js  # Module 4: Banner grabbing, version detection
│   │   └── webTechFingerprint.js  # Module 5: Wappalyzer-style tech detection
│   └── utils/
│       ├── exec.js            # CLI tool executor with timeout
│       └── riskScoring.js     # Risk score & grade calculator
└── frontend/
    └── src/
        ├── App.jsx            # Full React UI — all tabs and views
        └── App.css            # Dark theme styling
```

---

## Quick Start

### Option A: Direct (dev mode)

```bash
chmod +x setup.sh
./setup.sh
```

### Option B: Docker

```bash
./setup.sh docker
# or
docker-compose up --build
```

### Option C: Manual

```bash
# Backend
cd backend && npm install && node server.js

# Frontend (new terminal)
cd frontend && npm install && npm start
```

Open http://localhost:3000

---

## Security Tools

The platform works in two modes:

### Full Mode (with tools installed)
| Tool | Source | Used For |
|------|--------|----------|
| `subfinder` | ProjectDiscovery | Subdomain enumeration |
| `httpx` | ProjectDiscovery | Live host probing, CDN/WAF detection |
| `dnsx` | ProjectDiscovery | Bulk DNS resolution |
| `nmap` | Nmap.org | Port scanning + service version detection |

Install Go tools:
```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
```

### Fallback Mode (Node.js only)
If tools are not installed, the platform falls back to:
- DNS enumeration via Node.js `dns` module + common wordlist
- HTTP probing via `node-fetch`
- TCP socket scanning for port detection
- Header-based service fingerprinting

---

## Modules

### Module 1: Asset Discovery
- Subdomain enumeration (subfinder + DNS wordlist fallback)
- Live host validation (httpx / node-fetch)
- IP resolution (dnsx / Node.js dns)
- CDN/WAF/cloud provider detection
- Subdomain takeover detection

### Module 2: DNS & Email Security
- SPF record analysis (presence, policy strength, lookup count)
- DMARC validation (policy level, reporting config)
- DKIM key detection (common selectors)
- DNSSEC check
- Zone transfer (AXFR) testing

### Module 3: Port Scanning
- Top 1000 ports via nmap / common ports via TCP sockets
- Service identification
- Dangerous exposure flagging (Redis, MongoDB, Docker API, etc.)

### Module 4: Service Fingerprinting
- Banner grabbing
- Version extraction
- HTTP security header audit
- Known vulnerable version detection

### Module 5: Web Tech Fingerprinting
- HTTP headers, HTML, JavaScript, cookie analysis
- CMS detection (WordPress, Drupal, Joomla, Magento, Shopify)
- Framework detection (React, Angular, Vue, Next.js, Django, Laravel…)
- CDN detection (Cloudflare, Akamai, Fastly, CloudFront)
- Path probing for exposed admin panels, .env files, .git repos

---

## API Endpoints

```
POST   /api/scan/start          Start a new scan { domain }
GET    /api/scan                 List all scans
GET    /api/scan/:id             Get scan status + full results
DELETE /api/scan/:id             Cancel a running scan

GET    /api/report/:id/json      Full JSON report
GET    /api/report/:id/executive Executive summary

WS     ws://localhost:3001?scanId=<id>  Real-time scan progress
```

---

## Risk Scoring

Findings are scored by severity and aggregated into a 0–100 risk score:

| Grade | Score | Label |
|-------|-------|-------|
| A+/A | 0–20 | Low risk |
| B | 21–30 | Moderate |
| C | 31–45 | Elevated |
| D | 46–60 | High risk |
| E | 61–75 | Critical |
| F | 76–100 | Severe |

---

## Adding New Modules

1. Create `backend/modules/yourModule.js` — export `async function runYourModule(domain, onProgress)`
2. Return `{ findings: [], ...data }` — findings must have `{ id, severity, title, description, module, remediation }`
3. Add to the `moduleList` array in `routes/scan.js`
4. Add a new tab component in `frontend/src/App.jsx`

---

## Responsible Use

This tool is intended for authorized security assessments only. Always obtain explicit written permission before scanning any domain you do not own. Unauthorized scanning may violate computer fraud laws in your jurisdiction.
