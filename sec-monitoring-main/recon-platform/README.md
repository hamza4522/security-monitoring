# 🛡️ ReconScan — Agentless Security Assessment Platform

> **No agents. No Nessus license. No API keys required.**  
> Full external attack surface analysis from a single domain name.

Built with **React + Node.js** · Styled with a **Datadog-inspired dark theme** · Real-time via **WebSockets**

---

## 🗂️ Table of Contents

- [Features Overview](#-features-overview)
- [How It Works](#-how-it-works)
- [Module Deep Dives](#-module-deep-dives)
  - [Asset Discovery](#1--asset-discovery)
  - [SSL/TLS Scan](#2--ssltls-scan)
  - [DNS Assessment](#3--dns--email-security-assessment)
  - [Port Scanning](#4--port-scanning)
  - [Service Fingerprinting](#5--service-fingerprinting)
  - [Web Tech Fingerprinting](#6--web-technology-fingerprinting)
  - [WAF / CDN Detection](#7--waf--cdn-detection)
  - [Vulnerability Assessment](#8--vulnerability-assessment)
  - [Nuclei-Style Checks](#9--nuclei-style-checks)
  - [JavaScript Secret Scanner](#10--javascript-secret-scanner)
  - [Subdomain Takeover](#11--subdomain-takeover-detection)
  - [Active Web Attacks](#12--active-web-attack-scanner)
  - [CMS Vulnerability Scan](#13--cms-vulnerability-scan)
  - [CVE Enrichment](#14--nvd-cve-enrichment)
  - [Retire.js Checker](#15--retirejs-vulnerable-library-checker)
  - [API Discovery](#16--public-api-discovery)
  - [Nessus-Style Scanner](#17--nessus-style-vulnerability-scanner)
- [Scan Modes](#-scan-modes)
- [Risk Scoring](#-risk-scoring)
- [Quick Start](#-quick-start)
- [Architecture](#-architecture)
- [API Reference](#-api-reference)
- [Theming](#-theming)
- [Adding New Modules](#-adding-new-modules)
- [Responsible Use](#-responsible-use)

---

## ✨ Features Overview

| # | Module | What It Does |
|---|---|---|
| 1 | 🌐 Asset Discovery | Finds all subdomains, live hosts, IPs, CDN/WAF providers |
| 2 | 🔒 SSL/TLS Scan | Checks every certificate for expiry, misconfig, weak ciphers |
| 3 | 🗂️ DNS Assessment | Audits SPF, DMARC, DKIM, DNSSEC, zone transfer exposure |
| 4 | 🔭 Port Scan | Discovers open network ports across all targets |
| 5 | 🧬 Service Fingerprint | Identifies running services, versions, and HTTP security headers |
| 6 | 🧠 Web Tech Fingerprint | Detects CMS, frameworks, JS libraries, CDN, analytics tools |
| 7 | 🛡️ WAF/CDN Detection | Identifies firewall and CDN products protecting the target |
| 8 | ⚠️ Vulnerability Assessment | Checks for common misconfigurations and known CVEs |
| 9 | 🎯 Nuclei-Style Checks | Template-based checks for exposures, misconfigs, default pages |
| 10 | 📜 JS Secret Scanner | Extracts hardcoded API keys, tokens, credentials from JavaScript |
| 11 | 🔁 Subdomain Takeover | Detects dangling DNS records attackers can hijack |
| 12 | ⚔️ Active Web Attacks | Live probes for XSS, SQLi, CMDi, LFI, SSRF, XXE |
| 13 | 🏛️ CMS Vulnerability Scan | Plugin/theme CVEs for WordPress, Drupal, Joomla, Magento |
| 14 | 📡 CVE Enrichment | Matches detected tech versions to real NIST NVD CVE entries |
| 15 | 💊 Retire.js Checker | Flags vulnerable JavaScript libraries via Retire.js database |
| 16 | 🔗 API Discovery | Finds OpenAPI, GraphQL, REST, SOAP, and JS-extracted endpoints |
| 17 | 🔬 Nessus-Style Scanner | 50+ agentless plugin checks with CVSS scores and CVE references |

---

## 🔄 How It Works

1. You enter a target domain (e.g. `example.com`)
2. Choose **Full Scan** (domain + all subdomains) or **Single Domain** (fast, focused)
3. The backend pipeline runs all 17 modules **concurrently** where possible
4. Live progress streams to your browser via **WebSocket**
5. Findings are aggregated, scored, and displayed with full remediation guidance
6. Export results as **PDF**, **Markdown**, or **JSON**

---

## 🔍 Module Deep Dives

---

### 1. 🌐 Asset Discovery

**What it does:** Maps the complete attack surface of a domain by discovering every publicly accessible subdomain and host.

**How it works:**
- Runs `subfinder` (if installed) to passively enumerate subdomains from certificate transparency logs, DNS datasets, APIs (VirusTotal, Shodan, etc.)
- Falls back to a built-in 3,000+ word DNS wordlist, trying common prefixes like `www`, `api`, `mail`, `staging`, `dev`, `admin`, `cdn`, `vpn`, etc.
- Validates discovered names via DNS resolution using Node.js `dns` module or `dnsx`
- Probes each live host with HTTP/HTTPS to confirm accessibility
- Detects CDN, cloud provider, and WAF from HTTP response headers and CNAME patterns
- Checks for wildcard DNS records that may cause false positives

**Output:** List of confirmed live subdomains with their IPs, HTTP status codes, CDN/WAF tags, and redirect chains. This list is then fed into every subsequent module as the expanded target set.

---

### 2. 🔒 SSL/TLS Scan

**What it does:** Audits the TLS certificate configuration of every discovered host to detect misconfigurations, expiry, and cryptographic weaknesses.

**How it works:**
- Connects to port 443 on each target (primary domain + all subdomains in Full Scan mode)
- Reads the raw TLS certificate: subject, issuer, validity dates, key type and size, SAN entries
- Calculates days until expiry — flags anything under 30 days as urgent
- Checks for self-signed certificates (issuer = subject)
- Detects certificates covering unexpected domains in the Subject Alternative Names
- Verifies correct chain of trust and cipher suite strength
- Audits the HTTP response for `Strict-Transport-Security` (HSTS) header presence and strength

**Output:** Per-host certificate health table with expiry countdown, validity status (✅ Valid / ⚠️ Expiring / 🔴 Expired), grade, and HSTS configuration details.

---

### 3. 🗂️ DNS & Email Security Assessment

**What it does:** Audits all DNS records and email authentication standards to detect misconfigurations that enable email spoofing and data leakage.

**How it works:**

| Check | What It Tests |
|---|---|
| **SPF** | Is a Sender Policy Framework record present? Does it have a strict (`-all`) or permissive (`+all`) policy? Too many DNS lookups? |
| **DMARC** | Is a DMARC record at `_dmarc.domain` present? What is the enforcement policy (`none`, `quarantine`, `reject`)? |
| **DKIM** | Probes 30+ common DKIM selectors (`default`, `google`, `mail`, `k1`, `s1`, etc.) to find active signing keys |
| **DNSSEC** | Is DNSSEC enabled and are DS records present in the parent zone? |
| **Zone Transfer (AXFR)** | Attempts AXFR against each discovered nameserver — a successful transfer exposes the *entire* DNS zone |
| **CAA Records** | Are Certification Authority Authorization records present limiting which CAs can issue certificates? |
| **MX / NS / TXT** | Full enumeration of all DNS records |

**Why it matters:** Without SPF/DMARC, anyone on the internet can send emails that appear to come from your domain — enabling phishing attacks against your customers and employees.

---

### 4. 🔭 Port Scanning

**What it does:** Discovers all open TCP ports on every target host to understand what network services are exposed to the internet.

**How it works:**
- Uses `nmap` for fast SYN scanning if available
- Falls back to concurrent TCP socket probing in pure Node.js against the top ~1,000 ports
- Flags any dangerous services detected (see list below)
- Groups ports by service type (web, database, remote access, messaging)

**Dangerous services flagged immediately:**

| Port | Service | Risk |
|---|---|---|
| 22 | SSH | Brute-force target |
| 23 | Telnet | Plaintext credentials |
| 445 | SMB | EternalBlue / WannaCry surface |
| 3389 | RDP | BlueKeep, brute-force |
| 3306 | MySQL | Direct DB access |
| 5432 | PostgreSQL | Direct DB access |
| 6379 | Redis | No-auth data exposure |
| 9200 | Elasticsearch | Unauthenticated data access |
| 27017 | MongoDB | Unauthenticated data access |
| 2375 | Docker API | Full container/host control |

**Output:** Port table per host with service name, state (open/filtered), banner if captured, and a risk flag for dangerous exposures.

---

### 5. 🧬 Service Fingerprinting

**What it does:** Identifies exactly which software and version is running on each discovered service, and audits HTTP security headers.

**How it works:**
- Performs TCP banner grabbing on each open port (reads the first 512 bytes the service sends on connect)
- Parses version strings from SSH, FTP, SMTP, HTTP, and raw banners
- Sends HTTP `HEAD` and `GET` requests to extract `Server`, `X-Powered-By`, `Via`, and `X-Generator` headers
- Compares detected versions against a local list of known-vulnerable versions (Apache, Nginx, OpenSSH, vsftpd, etc.)
- Performs a full HTTP security header audit:

| Header | What Missing Means |
|---|---|
| `Strict-Transport-Security` | HTTPS not enforced — MITM downgrade possible |
| `Content-Security-Policy` | XSS attacks not mitigated |
| `X-Frame-Options` | Clickjacking attacks possible |
| `X-Content-Type-Options` | MIME sniffing attacks possible |
| `Referrer-Policy` | Sensitive URLs leaked to third parties |
| `Permissions-Policy` | Browser features (camera, mic) unrestricted |

**Output:** Per-host service table with version strings, vulnerability flags, and a header audit matrix.

---

### 6. 🧠 Web Technology Fingerprinting

**What it does:** Identifies the complete technology stack running behind a web application — CMS, frameworks, analytics, CDN, server, and more — across all targets.

**How it works:**
- Analyzes HTTP response headers, HTML source, JavaScript file names, `<meta>` tags, cookie names, and inline script patterns
- Uses a Wappalyzer-style rule database with 200+ technology signatures
- Groups detections by category with confidence level (High / Medium / Low) and evidence string

**Detects categories including:**

| Category | Examples |
|---|---|
| **CMS** | WordPress, Drupal, Joomla, Magento, Ghost, Wix, Squarespace |
| **Frameworks** | React, Vue, Angular, Next.js, Django, Laravel, Rails, Express |
| **Languages** | PHP, Python, Ruby, Java, ASP.NET |
| **Web Servers** | Nginx, Apache, IIS, Caddy, Litespeed |
| **CDN** | Cloudflare, Akamai, Fastly, CloudFront, Bunny, Vercel |
| **Analytics** | Google Analytics, Hotjar, Segment, Mixpanel |
| **Security** | reCAPTCHA, Sentry, Datadog RUM |
| **E-commerce** | WooCommerce, Shopify, Stripe |

**Why it matters:** Once you know the stack, you know which CVEs apply. This data directly feeds the CVE Enrichment module.

---

### 7. 🛡️ WAF / CDN Detection

**What it does:** Identifies whether a Web Application Firewall or CDN is protecting the target — and which product it is.

**How it works:**
- Sends deliberate probe requests including known attack patterns (SQLi strings, XSS payloads, path traversal)
- Analyzes the response: status code (403/406/429/503), response body (`blocked`, `access denied`, `security`), and specific headers (`CF-Ray`, `X-Sucuri-ID`, `X-Denied-Reason`, etc.)
- Checks CNAME records for CDN provider domains
- Matches Server and Via headers

**Detects 20+ products** including: Cloudflare, AWS WAF, Azure Front Door, Akamai Kona, Imperva / Incapsula, Sucuri, ModSecurity, F5 BIG-IP, Fastly, Vercel, Netlify.

**Why it matters:** A WAF changes the attack strategy. Direct-to-origin attacks may bypass it. Knowing which CDN is used also reveals infrastructure providers and potential cache poisoning opportunities.

---

### 8. ⚠️ Vulnerability Assessment

**What it does:** Runs a comprehensive set of checks for common web misconfigurations, exposure of sensitive paths, and known CVEs based on the detected technology stack.

**How it works:**
- Probes for 80+ known sensitive paths (`.git`, `.env`, `phpinfo.php`, `web.config`, `backup.sql`, etc.)
- Tests for misconfigured HTTP methods (TRACE, PUT, DELETE)
- Checks for outdated software versions against a vulnerability database
- Looks for admin panels, exposed APIs, database UIs, and monitoring dashboards
- Validates cookie security attributes (Secure, HttpOnly, SameSite)
- Tests for insecure CORS policies

**Output:** Severity-rated findings with descriptions and step-by-step remediation guidance for each issue.

---

### 9. 🎯 Nuclei-Style Checks

**What it does:** Runs a library of template-based checks to detect specific known-vulnerable endpoints, default pages, misconfigurations, and exposed panels — similar to how ProjectDiscovery's Nuclei tool works.

**How it works:**
- Each "template" targets a specific condition: e.g., "Does `/adminer.php` return a database login page?"
- Templates cover:
  - **Default installation pages** (Apache default, IIS default, Nginx welcome)
  - **Exposed admin panels** (Tomcat Manager, phpMyAdmin, Grafana, Jenkins, Portainer)
  - **Tech-specific endpoints** (Laravel debug, Spring Boot Actuator, Django debug page)
  - **Cloud metadata endpoints** (`http://169.254.169.254/latest/meta-data/` — SSRF canary)
  - **Backup and config file exposure**
  - **Version-specific CVE triggers**

**Output:** Template name, matched evidence, affected URL, and severity rating.

---

### 10. 📜 JavaScript Secret Scanner

**What it does:** Downloads and analyzes every JavaScript file loaded by the target page, searching for hardcoded credentials, API keys, tokens, and other secrets that developers accidentally committed to their frontend code.

**How it works:**
- Fetches the target page and extracts all `<script src="...">` URLs
- Downloads each JS file (including bundled React/Vue/Angular apps)
- Applies 50+ regex patterns to the raw source code looking for secrets

**Secret types detected:**

| Pattern | Example |
|---|---|
| **AWS Access Keys** | `AKIA...` |
| **AWS Secret Keys** | 40-char alphanumeric after `aws_secret` |
| **Google API Keys** | `AIza...` |
| **GitHub Tokens** | `ghp_...`, `github_pat_...` |
| **Stripe Keys** | `sk_live_...`, `pk_live_...` |
| **JWT Tokens** | `eyJ...` (decoded to show claims) |
| **Private RSA/EC Keys** | `-----BEGIN PRIVATE KEY-----` |
| **Slack Webhooks** | `https://hooks.slack.com/...` |
| **SendGrid / Mailgun Keys** | `SG.`, `key-...` |
| **Basic Auth in URLs** | `https://user:password@...` |
| **Hardcoded Passwords** | `password = "..."`, `pwd: "..."` |
| **Database Connection Strings** | `mongodb://user:pass@host` |

**Why it matters:** Single-page applications frequently expose production API keys in their JavaScript bundles. This is one of the most common and high-impact findings in real-world bug bounty programs.

---

### 11. 🔁 Subdomain Takeover Detection

**What it does:** Identifies subdomains with dangling DNS records that an attacker could claim and take over to host malicious content under your domain name.

**How it works:**
- Takes the full list of subdomains discovered in Asset Discovery
- For each subdomain: resolves its CNAME chain
- Checks if the final CNAME points to a cloud service (S3, GitHub Pages, Heroku, Azure, Netlify, Vercel, Fastly, etc.)
- Attempts to fetch the target URL and checks the response body for **"unclaimed" fingerprints** — specific error messages each provider shows when a resource is deleted but the DNS still points to them

**Fingerprints checked for 30+ services** including:

| Service | Unclaimed Response Pattern |
|---|---|
| **GitHub Pages** | `There isn't a GitHub Pages site here` |
| **AWS S3** | `NoSuchBucket`, `The specified bucket does not exist` |
| **Heroku** | `No such app`, `herokucdn.com` 404 |
| **Azure** | `404 Web Site not found` |
| **Netlify** | `Not Found - Request ID` |
| **Shopify** | `Sorry, this shop is currently unavailable` |
| **Ghost (Fastly)** | `The thing you were looking for is no longer here` |

**Why it matters:** If a subdomain like `assets.yourcompany.com` points via CNAME to a deleted S3 bucket, an attacker can create that S3 bucket and serve malicious content (phishing pages, malware) from `assets.yourcompany.com`. This is a well-documented class of vulnerability found in thousands of real companies.

---

### 12. ⚔️ Active Web Attack Scanner

**What it does:** Actively probes the target for exploitable web vulnerabilities by sending real attack payloads and inspecting the responses — the same approach used by Burp Suite's active scanner.

**How it works:**
- Crawls the target for forms, URL parameters, and input fields
- Sends attack payloads for each vulnerability class and checks the response

**Vulnerability classes tested:**

| Class | How It's Tested |
|---|---|
| **Reflected XSS** | Injects `<script>alert(1)</script>` into GET/POST params, checks if reflected unescaped |
| **SQL Injection** | Injects `'`, `" OR 1=1--`, `; DROP TABLE` — checks for database error messages |
| **Command Injection (CMDi)** | Injects `;id;`, `\|whoami\|`, `` `id` `` — checks for command output in response |
| **Local File Inclusion (LFI)** | Injects `../../etc/passwd` into path params — checks for `/root:x:0:0` in response |
| **Remote File Inclusion (RFI)** | Injects external URL — checks if fetched |
| **SSRF (Server-Side Request Forgery)** | Injects internal IPs (`169.254.169.254`) and localhost URLs |
| **XXE (XML External Entity)** | Injects XML entity payloads into XML-accepting endpoints |
| **Path Traversal** | Tests `../` sequences in file-related parameters |
| **Open Redirect** | Injects `//evil.com` and `https://evil.com` into redirect parameters |

⚠️ **Note:** These are real probes sent to the target. Only run against systems you are authorized to test.

---

### 13. 🏛️ CMS Vulnerability Scan

**What it does:** When a CMS is detected, runs targeted checks for CMS-specific vulnerabilities — exposed configuration files, vulnerable plugins, default credentials, and version-specific CVEs.

**How it works per CMS:**

**WordPress:**
- Checks `/wp-json/wp/v2/users` for user enumeration (leaks usernames without auth)
- Checks `readme.html` for version disclosure
- Fetches `wp-login.php` and tests default `admin/admin` credentials
- Probes for 50+ known-vulnerable plugin paths (e.g., `/wp-content/plugins/revslider/`)
- Checks `xmlrpc.php` exposure (brute-force amplification)
- Tests `wp-cron.php` accessibility (DoS vector)

**Drupal:**
- Checks `CHANGELOG.txt` for version disclosure
- Tests `update.php` access (privilege escalation)
- Probes for Drupalgeddon2 (CVE-2018-7600) indicators

**Joomla:**
- Checks `administrator/` panel accessibility
- Reads `README.txt` for version
- Tests `configuration.php.bak` exposure

**Magento:**
- Checks `/downloader/` Magento Connect
- Tests `/admin/` and `/index.php/admin/` panel
- Verifies Magento version from `RELEASE_NOTES.md`

**Output:** CMS name and version, exposed endpoints, severity-rated findings with CVE references where applicable.

---

### 14. 📡 NVD CVE Enrichment

**What it does:** Takes the list of technologies and version numbers detected by the Web Tech Fingerprinting module and looks up matching CVEs in the NIST National Vulnerability Database (NVD).

**How it works:**
- Sends the detected technology name and version to the NVD API (`services.nvd.nist.gov/rest/json/cves/2.0`)
- Parses the response to extract CVE IDs, CVSS scores, descriptions, and affected version ranges
- Filters results to only include CVEs where the detected version falls within the vulnerable range
- Ranks by CVSS score (Critical ≥ 9.0, High ≥ 7.0)

**Example enrichment flow:**
```
Detected: WordPress 6.3.1
→ NVD Query: "WordPress 6.3"
→ Matched CVEs: CVE-2023-38000 (CVSS 6.4), CVE-2023-39999 (CVSS 4.3)
→ Both displayed with descriptions, affected versions, and patch guidance
```

**Why it matters:** Turns version information from passive detection into actionable, referenced vulnerability data without requiring manual CVE research.

---

### 15. 💊 Retire.js Vulnerable Library Checker

**What it does:** Scans all JavaScript files loaded by the target against the [Retire.js](https://retirejs.github.io/retire.js/) vulnerability database — a community-maintained list of JavaScript libraries with known security issues.

**How it works:**
- Downloads the Retire.js vulnerability database (JSON)
- Extracts all JS file URLs from the target page
- For each file: attempts to identify the library name and version from filename patterns (`jquery-3.4.1.min.js`), file content comments (`/*! jQuery v3.4.1 */`), or inline version variables
- Cross-references detected `library@version` against the Retire.js database
- Returns matched vulnerabilities with CVE IDs and severity

**Common findings:**
- jQuery < 3.5.0 — XSS via `$.parseHTML()` (CVE-2020-11022)
- Bootstrap < 4.3.1 — XSS in `data-template` (CVE-2019-8331)
- Lodash < 4.17.21 — Prototype pollution (CVE-2021-23337)
- Moment.js < 2.29.4 — ReDoS (CVE-2022-31129)
- Angular < 1.8.3 — Multiple XSS vectors

**Why it matters:** Frontend JavaScript dependencies are frequently outdated and never updated. Vulnerable client-side libraries are a top source of XSS vulnerabilities across the web.

---

### 16. 🔗 Public API Discovery

**What it does:** Systematically enumerates all publicly accessible API endpoints exposed by the target, including documented and undocumented APIs.

**How it works via 9 detection techniques:**

| Technique | How |
|---|---|
| **OpenAPI / Swagger** | Probes `/swagger.json`, `/openapi.yaml`, `/api-docs`, `/v1/api-docs`, `/v3/api-docs` — parses spec to extract all documented endpoints |
| **GraphQL Detection** | Probes `/graphql`, `/gql`, `/api/graphql` — sends introspection query to enumerate full schema (types, queries, mutations) |
| **REST Endpoint Probing** | Tests 200+ common REST paths (`/api/users`, `/api/v1/health`, `/api/status`, `/api/me`, etc.) |
| **WSDL / SOAP** | Probes for `.wsdl` and `?wsdl` endpoints — parses service operations from the WSDL definition |
| **JavaScript Extraction** | Parses all JS bundles for `fetch()`, `axios.get/post`, `XMLHttpRequest` calls and extracts the URL strings |
| **robots.txt / sitemap.xml** | Reads `Disallow` and `<loc>` entries that often reveal hidden API paths |
| **Form Analysis** | Parses HTML `<form action="...">` elements to find submission endpoints |
| **Link Extraction** | Extracts all `<a href>` and resource URLs from the HTML |
| **Response Key Analysis** | For discovered JSON endpoints, reads the response body and extracts top-level key names to reveal data structure |

**Output:** Organized by source — OpenAPI specs with full endpoint lists, GraphQL schema types (flagging if introspection is enabled, which is a security risk), REST endpoints with HTTP status and auth requirements, JS-extracted URLs, and WSDL service operations.

**Why it matters:** Companies frequently expose internal APIs, admin APIs, or debug endpoints that were never meant to be public. Unauthenticated GraphQL with introspection enabled leaks the entire data schema. WSDL exposure reveals all service operations to attackers.

---

### 17. 🔬 Nessus-Style Vulnerability Scanner

**What it does:** Replicates the behavior of Tenable Nessus plugins — performing 50+ structured vulnerability checks across 11 plugin families — entirely without a Nessus license or installation. Each check produces a finding with a Plugin ID, CVSS score, CVE references, and remediation guidance.

**Plugin families and what they check:**

**🌐 Web Servers**
- Detects server version disclosure (`Server: Apache/2.4.49`) and maps to known CVEs
- Apache 2.4.49/2.4.50: CVE-2021-41773 Path Traversal/RCE (CVSS 9.8)
- Apache HTTP Request Smuggling: CVE-2023-25690
- Nginx version CVEs
- IIS end-of-life detection
- HTTP TRACE method enabled (XST / CVE-2003-1567)
- HTTP PUT method enabled (arbitrary file upload)
- Dangerous methods via OPTIONS disclosure

**🔐 TLS/SSL**
- TLS 1.0 protocol support (POODLE/BEAST — CVE-2014-3566)
- SSL certificate expiry (exact days remaining)
- Self-signed certificate detection
- Weak RSA key size (< 2048 bits)
- HSTS missing or too short max-age
- HSTS missing `includeSubDomains`

**🔑 Authentication**
- HTTP Basic Auth transmitted over plain HTTP (credential exposure)
- Anonymous FTP login accepted
- Telnet service running (plaintext remote access)
- Admin panel exposure: Tomcat Manager, Jenkins, Grafana, phpMyAdmin, Portainer
- Default credential testing: `admin/admin` against each detected panel

**📁 Information Disclosure (30+ checks)**
`.git/HEAD`, `.git/config`, `.env`, `.env.production`, `wp-config.php`, `phpinfo.php`, `/server-status`, `/actuator`, `/actuator/env`, `/actuator/heapdump`, `/metrics` (Prometheus), `dump.sql`, `backup.sql`, `config.json`, `docker-compose.yml`, `Dockerfile`, `.htpasswd`, `credentials.json` (GCP), `elmah.axd`, `trace.axd`, and more

**💉 Injection**
- SQL error-based injection detection (tests 5 URL patterns, matches 12 error patterns)
- Reflected XSS payload in response
- Path traversal to `/etc/passwd`

**🌍 Network Services (13 dangerous ports)**
SMB (EternalBlue — CVE-2017-0144), RDP (BlueKeep — CVE-2019-0708), VNC, Redis (CVE-2022-0543), Elasticsearch, MongoDB, MySQL, PostgreSQL, MSSQL, unencrypted Docker API (CVE-2019-5736), Kafka, ActiveMQ (CVE-2023-46604 — CVSS 10.0), Oracle WebLogic (CVE-2023-21839)

**🐚 CGI**
- Shellshock via User-Agent header (CVE-2014-6271 — CVSS 10.0)
- Heartbleed certificate date heuristic (CVE-2014-0160)

**📋 Security Policy**
- Content-Security-Policy missing or contains `unsafe-inline`/`unsafe-eval`/wildcard
- X-Frame-Options missing (Clickjacking)
- X-Content-Type-Options missing
- Referrer-Policy missing
- Permissions-Policy missing

**🍪 CORS & Cookies**
- CORS `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true` (critical — credential theft)
- CORS origin reflection (any site can make authenticated requests)
- Session cookie missing `Secure` flag
- Session cookie missing `HttpOnly` flag
- Cookie missing `SameSite` flag (CSRF risk)

**🌐 DNS**
- AXFR zone transfer attempt against all nameservers
- SPF record missing (email spoofing)
- DMARC record missing

**Output:** Plugin results sorted by severity with Plugin ID, CVSS score, CVE links to NVD, technical detail (what was found), and remediation. Filterable by plugin family and severity. Scan metadata panel shows engine, policy, target IP, and timestamp.

---

## 🎯 Scan Modes

| Mode | What Gets Scanned | Best For | Typical Duration |
|---|---|---|---|
| 🌐 **Full Scan** | Primary domain + all discovered subdomains (can be 10–100+ targets) | Comprehensive assessment, bug bounty, security audits | 2–10 minutes |
| 🎯 **Single Domain** | Primary domain only — no subdomain discovery or expansion | Quick spot-checks, CI/CD integration, retesting a single fix | 30–90 seconds |

Select the mode in the scan box before launching. The mode is saved per-scan and displayed as a badge in the history table.

---

## 📊 Risk Scoring

All findings are weighted by severity and aggregated into a **0–100 risk score** with a letter grade:

| Grade | Score Range | Label | Meaning |
|---|---|---|---|
| **A+** | 0–10 | Excellent | No significant issues found |
| **A** | 11–20 | Low Risk | Minor findings only |
| **B** | 21–30 | Moderate | Some issues to address |
| **C** | 31–45 | Elevated | Multiple medium/high findings |
| **D** | 46–60 | High Risk | Critical exposures present |
| **E** | 61–75 | Critical | Severe vulnerabilities found |
| **F** | 76–100 | Severe | Immediate action required |

**Scoring weights:** Critical finding = 20 pts · High = 10 pts · Medium = 3 pts · Low = 1 pt

---

## 🚀 Quick Start

### Option A: Manual (Dev Mode)

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

### Option B: Setup Script

```bash
cd recon-platform
chmod +x setup.sh && ./setup.sh
```

### Option C: Docker

```bash
cd recon-platform
docker-compose up --build
```

---

## 🏗️ Architecture

```
recon-platform/
├── backend/
│   ├── server.js                   # Express + WebSocket server, scan persistence
│   ├── routes/
│   │   ├── scan.js                 # Pipeline orchestrator — runs all 17 modules
│   │   └── report.js               # PDF / Markdown / JSON report generation
│   ├── modules/
│   │   ├── assetDiscovery.js       # Subdomain enum, live probing, CDN detection
│   │   ├── sslScan.js              # TLS cert analysis across all subdomains
│   │   ├── dnsAssessment.js        # SPF, DMARC, DKIM, DNSSEC, AXFR
│   │   ├── portScan.js             # TCP port scanning (nmap + fallback)
│   │   ├── serviceFingerprint.js   # Banner grab, version detection, headers
│   │   ├── webTechFingerprint.js   # 200+ technology signatures
│   │   ├── wafDetector.js          # 20+ WAF/CDN fingerprints
│   │   ├── vulnAssessment.js       # Misconfiguration & CVE checks
│   │   ├── nucleiChecks.js         # Template-based exposure detection
│   │   ├── jsSecretScanner.js      # 50+ secret patterns in JS files
│   │   ├── subdomainTakeover.js    # Dangling CNAME detection (30+ services)
│   │   ├── wapitiscan.js           # Active XSS/SQLi/CMDi/LFI/SSRF probes
│   │   ├── cmsVulnScan.js          # WordPress, Drupal, Joomla, Magento CVEs
│   │   ├── cveEnrichment.js        # NIST NVD CVE lookup by detected version
│   │   ├── retireJsChecker.js      # Retire.js vulnerable library matching
│   │   ├── apiDiscovery.js         # OpenAPI, GraphQL, REST, WSDL, JS endpoints
│   │   └── nessusScanner.js        # 50+ agentless Nessus-style plugin checks
│   └── utils/
│       ├── exec.js                 # CLI tool runner with timeout
│       ├── riskScoring.js          # 0–100 score + A–F grade calculator
│       └── alertEngine.js          # Webhook / Slack / Discord / Email alerts
└── frontend/
    └── src/
        ├── App.jsx                 # Full React UI — 17 module tabs + Dashboard
        ├── App.css                 # Layout, animations, all component styles
        └── theme.css               # Datadog-style CSS variable color tokens
```

---

## 🛠️ Optional Security Tools

The platform works fully without these — Node.js fallbacks are built in. Installing them improves subdomain discovery and port scanning speed:

| Tool | Install | Enhancement |
|---|---|---|
| `subfinder` | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` | 10x more subdomains via passive APIs |
| `httpx` | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` | Faster live host probing with CDN tagging |
| `dnsx` | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` | Bulk DNS resolution with wildcard filtering |
| `nmap` | Download from nmap.org | Faster and more accurate port scanning |

---

## 📡 API Reference

```
POST   /api/scan/start                  Start scan
                                        Body: { domain, scanMode: 'full'|'single' }
GET    /api/scan                        List all scans (sorted by startedAt desc)
GET    /api/scan/:id                    Full scan object with all module results
DELETE /api/scan/:id                    Cancel a running scan
GET    /api/scan/compare?a=:id&b=:id   Diff two completed scans (new/fixed findings)

GET    /api/report/:id/pdf              Download PDF executive report
GET    /api/report/:id/markdown         Download Markdown report
GET    /api/report/:id/download         Download full JSON results
GET    /api/report/:id/executive        Executive summary JSON

WS     ws://localhost:3001?scanId=:id   Real-time scan events:
                                          module_start, module_progress,
                                          module_complete, module_error,
                                          scan_complete
```

---

## 🎨 Theming

The UI uses a **Datadog-inspired dark theme** built entirely on CSS custom properties. Edit `frontend/src/theme.css` to rebrand — changes hot-reload instantly:

```css
--bg-main:        #0f1014;    /* Page background */
--accent-blue:    #7b4fff;    /* Primary (Datadog purple) */
--accent-orange:  #ff6b2b;    /* Warnings (Datadog orange) */
--accent-green:   #2dc771;    /* Success */
--accent-red:     #f23b4d;    /* Critical */
--text-muted:     #8a8fa8;    /* Secondary text */
```

---

## ⌨️ Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl+K` | Global finding search across all scans |
| `Ctrl+N` | Focus domain input / new scan |
| `Ctrl+H` | Go to Scan History |
| `Ctrl+D` | Go to Dashboard |
| `?` | Open keyboard shortcuts modal |
| `Esc` | Close any open modal |

---

## 🧩 Adding New Modules

1. Create `backend/modules/yourModule.js`:
```js
async function runYourModule(domain, onProgress) {
  onProgress('Starting...');
  // ... your logic
  return {
    findings: [
      {
        id: 'YOUR-001',
        severity: 'high',           // critical | high | medium | low | info
        title: 'Finding Title',
        description: 'What was found and why it matters.',
        module: 'yourModule',
        remediation: 'How to fix it.',
      }
    ],
    // ... any other data your UI tab needs
  };
}
module.exports = { runYourModule };
```

2. Register in `routes/scan.js` `moduleList`:
```js
{ key: 'yourModule', label: 'Your Module Label', weight: 8, runner: runYourModule }
```

3. Add initial state in the scan object (`modules: { yourModule: { status: 'pending', data: null } }`)

4. Add a React tab component in `frontend/src/App.jsx`

---

## ⚠️ Responsible Use

This tool is intended for **authorized security assessments only**.

- Only scan domains you own or have **explicit written permission** to test
- Active attack modules (web attacks, default credential probing) send real payloads to the target
- Unauthorized scanning may violate the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, GDPR, and equivalent laws in your jurisdiction
- The authors accept no liability for misuse of this software
