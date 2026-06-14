# ReconScan — Agentless Security Assessment Platform

A modular, full-stack external security reconnaissance platform. No agents or software installed on the target. Built with **React + Node.js**. Scans any domain and surfaces vulnerabilities, misconfigurations, public APIs, exposed secrets, and real CVE data — all from one dashboard.

---

## ✨ What's New (Latest Update)

| Feature | Description |
|---|---|
| 🔗 **Public API Discovery** | Enumerates Swagger/OpenAPI specs, GraphQL endpoints, REST paths, WSDL/SOAP, JS-extracted API calls, robots.txt, form actions |
| 📋 **NVD CVE Enrichment** | Queries the NIST National Vulnerability Database (CVE API v2) for real CVEs based on detected technologies |
| 📦 **Retire.js Integration** | Scans JS libraries loaded on target pages against the Retire.js vulnerability database |
| 🛡️ **Vulnerability Assessment Tab** | New dedicated tab showing all 120+ security checks with pass/fail/warn/info filtering by category |
| 🐛 **False Positive Fixes** | Soft-404 detection now uses body-length comparison; CVE header patterns now require version numbers |

---

## Architecture

```
recon-platform/
├── backend/
│   ├── server.js                  # Express + WebSocket API, persistence layer
│   ├── routes/
│   │   ├── scan.js                # Scan orchestration & 18-module pipeline
│   │   └── report.js              # PDF / Markdown / JSON report generation
│   ├── modules/
│   │   ├── assetDiscovery.js      # Subdomain enum, live hosts, CDN/WAF
│   │   ├── dnsAssessment.js       # SPF, DMARC, DKIM, DNSSEC, zone transfer
│   │   ├── portScan.js            # nmap / TCP socket port scanning
│   │   ├── serviceFingerprint.js  # Banner grabbing, version detection
│   │   ├── webTechFingerprint.js  # Wappalyzer-style tech stack detection
│   │   ├── vulnAssessment.js      # 120+ HTTP/SSL/cookie/file exposure checks
│   │   ├── nucleiChecks.js        # Template-based vulnerability probes
│   │   ├── sslScan.js             # TLS cert validity, cipher, chain checks
│   │   ├── wafDetector.js         # WAF / CDN fingerprinting
│   │   ├── jsSecretScanner.js     # API keys / secrets in JavaScript files
│   │   ├── subdomainTakeover.js   # Dangling CNAME / takeover detection
│   │   ├── wapitiscan.js          # Active web attack simulation
│   │   ├── cmsVulnScan.js         # CMS-specific vulnerability checks
│   │   ├── cveEnrichment.js       # ★ NVD CVE API v2 real-time lookups
│   │   ├── retireJsChecker.js     # ★ Retire.js vulnerable library scanner
│   │   ├── apiDiscovery.js        # ★ Public API endpoint enumeration
│   │   └── whoisLookup.js         # WHOIS, IP geolocation, ASN info
│   └── utils/
│       ├── exec.js                # CLI tool executor with timeout
│       └── riskScoring.js         # Risk score & grade calculator
└── frontend/
    └── src/
        ├── App.jsx                # Full React UI — 20 tabs across all modules
        └── App.css                # Dark glassmorphism theme
```

---

## Quick Start

### Option A: Manual (Recommended for dev)

```bash
# Backend
cd recon-platform/backend
npm install
node server.js
# → Listening on http://localhost:3001

# Frontend (new terminal)
cd recon-platform/frontend
npm install
npm start
# → Open http://localhost:3000
```

### Option B: Docker

```bash
docker-compose up --build
```

Open **http://localhost:3000**

---

## Security Modules (18 total)

### 🔍 Reconnaissance
| Module | What It Does |
|--------|-------------|
| **WHOIS & IP Intel** | WHOIS lookup, IP geolocation, ASN/ISP info |
| **Asset Discovery** | Subdomain enumeration via subfinder + DNS wordlist, live host probing |
| **DNS & Email Security** | SPF, DMARC, DKIM, DNSSEC, zone transfer (AXFR) |
| **Port Scanning** | Top 1000 ports via nmap (or TCP socket fallback), dangerous exposure flagging |
| **Service Fingerprinting** | Banner grabbing, version extraction, HTTP header audit |
| **Web Tech Fingerprinting** | CMS, framework, CDN, JavaScript library detection |
| **WAF / CDN Detection** | Cloudflare, Akamai, AWS WAF, Fastly fingerprinting |

### 🛡️ Vulnerability Assessment
| Module | What It Does |
|--------|-------------|
| **Vulnerability Assessment** | 120+ checks: security headers, cookies, sensitive file exposure, CORS, CSRF, clickjacking, SSL config |
| **SSL/TLS Scan** | Certificate validity, expiry, cipher strength, chain validation |
| **Nuclei-style Checks** | Template-based CVE probes, panel detection, tech misconfig |
| **CMS Vulnerability Scan** | WordPress/Drupal/Joomla/Magento-specific vulnerability probes |
| **Active Web Attacks** | SQL injection, XSS, command injection, path traversal probing |

### 🔎 Advanced Intelligence
| Module | What It Does |
|--------|-------------|
| **NVD CVE Enrichment** ★ | Queries NIST NVD CVE API v2 for real CVEs matched to detected technologies. Returns CVSS scores, published dates, NVD links |
| **Retire.js Library Check** ★ | Downloads live Retire.js database, scans target JS files for vulnerable jQuery/Bootstrap/Angular/etc. |
| **Public API Discovery** ★ | 9-technique API enumeration: Swagger/OpenAPI (30+ paths), GraphQL introspection, REST probing (45+ paths), JS file parsing, robots.txt, sitemap, form actions, WSDL/SOAP, well-known endpoints |
| **JS Secret Scanner** | API keys, tokens, credentials extracted from JavaScript files |
| **Subdomain Takeover** | Dangling CNAME detection across all discovered subdomains |

---

## Optional: NVD API Key (faster CVE lookups)

The CVE enrichment module works without a key but is rate-limited. Get a **free key** from https://nvd.nist.gov/developers/request-an-api-key

Create `recon-platform/backend/.env`:
```
NVD_API_KEY=your-free-key-here
```
With a key: 50 requests/30s. Without: 5 requests/30s (6s delays between queries).

---

## External Tools (Optional)

The platform has pure Node.js fallbacks for everything. CLI tools enhance accuracy:

| Tool | Source | Used For |
|------|--------|----------|
| `subfinder` | ProjectDiscovery | Faster subdomain enumeration |
| `httpx` | ProjectDiscovery | Live host probing with CDN/WAF detection |
| `dnsx` | ProjectDiscovery | Bulk DNS resolution |
| `nmap` | Nmap.org | Full port scanning + service version detection |

```bash
# Install Go tools (optional)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
```

---

## Frontend Tabs

After a scan completes, results are shown across **20 tabs**:

| Tab | Description |
|-----|-------------|
| Overview | Risk score, finding summary, top issues |
| 🌐 WHOIS & IP | Registrar, IP, ASN, geolocation |
| Assets | Subdomains, live hosts, IPs, cloud providers |
| 🔒 SSL/TLS | Certificate validity, cipher analysis |
| DNS & Email | SPF/DMARC/DKIM/DNSSEC status |
| Ports | Open ports, service banners |
| Services | Fingerprinted services with version info |
| Web Tech | Detected stack: CMS, framework, CDN, libraries |
| WAF/CDN | WAF provider detection, bypass indicators |
| 🛡 Vuln Assess | 120+ security checks with category filtering |
| 🎯 Nuclei | Template-based CVE and misconfig findings |
| 📋 CVE Lookup | Real NVD CVEs for detected technologies |
| 📦 Retire.js | Vulnerable JavaScript libraries |
| 🔗 API Discover | Public APIs: Swagger, GraphQL, REST, JS-extracted |
| JS Secrets | API keys / tokens found in JavaScript |
| Takeover | Subdomain takeover vulnerability status |
| ⚔ Web Attacks | Active attack probe results |
| 🏛 CMS | CMS-specific vulnerability findings |
| Findings | All findings filterable by severity |
| Live Log | Real-time scan progress log |

---

## Backend API

```
POST   /api/scan/start                Start a new scan  { domain }
GET    /api/scan                      List all scans
GET    /api/scan/:id                  Get scan status + full results
DELETE /api/scan/:id                  Cancel a running scan

GET    /api/report/:id/pdf            Download PDF report
GET    /api/report/:id/markdown       Download Markdown report
GET    /api/report/:id/download       Download JSON report

GET    /api/alerts/rules              List alert rules
PUT    /api/alerts/rules/:id          Update alert rule
GET    /api/alerts/config             Get notification config
PUT    /api/alerts/config             Update notification config (Slack/Discord/webhook/email)
POST   /api/alerts/test               Fire a test alert

WS     ws://localhost:3001?scanId=<id>  Real-time progress stream
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
3. Import and add to the `moduleList` array in `routes/scan.js`
4. Add the initial state key in the `modules` object in `routes/scan.js`
5. Create a tab component in `frontend/src/App.jsx` and wire it in `ScanView`

---

## Responsible Use

This tool is intended for **authorized security assessments only**. Always obtain explicit written permission before scanning any domain you do not own. Unauthorized scanning may violate computer fraud laws in your jurisdiction.

> **NVD Attribution:** This product uses data from the NVD API but is not endorsed or certified by the NVD.  
> **Retire.js:** Vulnerability data sourced from [github.com/RetireJS/retire.js](https://github.com/RetireJS/retire.js)
