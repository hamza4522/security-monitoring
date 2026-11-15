# Tool Capabilities

This security assessment platform is an agentless external reconnaissance, attack surface analysis, and active vulnerability scanning tool. It automates 20+ specialized security checks against target domains and subdomains.

## Scanning Modes
* **🌐 Full Scan**: Discovers all subdomains using Certificate Transparency logs and DNS brute-forcing, then runs all modules against every discovered host.
* **🎯 Single Domain**: Runs all modules against the primary domain only (fast and focused).
* **⚙️ Custom Scan**: Allows granular selection of which modules to execute, enabling targeted assessments.

## Reconnaissance Modules
1. **WHOIS & IP Intel** (`whoisLookup`)
   - Retrieves domain registration, registrar info, creation/expiry dates.
   - Identifies hosting providers, IP organization, AS numbers, and geolocation.
2. **Asset Discovery** (`assetDiscovery`)
   - Subdomain enumeration via crt.sh (Certificate Transparency).
   - Identifies related attack surface assets.
3. **DNS Assessment** (`dnsAssessment`)
   - Resolves A, AAAA, MX, TXT, NS, CNAME, SOA records.
   - Checks for missing or misconfigured SPF, DMARC, and DKIM records to detect email spoofing risks.
4. **SSL/TLS Scan** (`sslScan`)
   - Checks certificate validity, issuer, and expiration.
   - Detects weak protocols, weak cipher suites, missing HSTS headers, and misconfigured certificate chains.
5. **Port Scanning** (`portScan`)
   - Scans common HTTP/HTTPS, Database (MySQL, PostgreSQL, Redis), SSH, FTP, and remote management ports.
6. **Service Fingerprinting** (`serviceFingerprint`)
   - Identifies HTTP headers (Server, X-Powered-By) and backend service versions.
7. **Web Tech Fingerprinting** (`webTechFingerprint`)
   - Analyzes DOM elements, headers, and scripts to identify frameworks (React, Vue, Angular), CMS (WordPress), and infrastructure (Nginx, Apache).
8. **WAF / CDN Detection** (`wafDetector`)
   - Detects the presence of Web Application Firewalls (Cloudflare, AWS WAF, Akamai, Imperva) and CDNs.

## Vulnerability Assessment Modules
9. **Vuln Assessment** (`vulnAssessment`)
   - Broad security header checks (X-Frame-Options, CSP, X-Content-Type-Options).
   - Missing security headers and basic misconfigurations.
10. **Nuclei-style Checks** (`nucleiChecks`)
    - Probes for exposed admin panels, sensitive configuration files (e.g., `.env`, `web.config`), and known template-based CVEs.
11. **Web Attacks** (`wapitiscan`)
    - Active probing for SQL Injection, Cross-Site Scripting (XSS), OS Command Injection, and Path Traversal vulnerabilities.
12. **CMS Scan** (`cmsVulnScan`)
    - CMS-specific vulnerability probes for WordPress, Drupal, Joomla, and Magento.
13. **Nessus Scan** (`nessusScanner`)
    - Simulates Nessus-style vulnerability scanning results.
14. **Cookie Security** (`cookieSecurityScanner`)
    - Comprehensive analysis of cookies for missing `Secure`, `HttpOnly`, and `SameSite` flags.
    - Detects overly broad cookie domains and exposed JWT/session tokens.
15. **SRI Check** (`sriScanner`)
    - Audits external scripts and stylesheets for missing Subresource Integrity (SRI) attributes.
    - Validates existing hashes for accuracy.

## Intelligence & Advanced Modules
16. **JS Secrets** (`jsSecretScanner`)
    - Analyzes JavaScript files for hardcoded API keys, JWTs, AWS credentials, and access tokens.
17. **Subdomain Takeover** (`subdomainTakeover`)
    - Detects dangling CNAME records pointing to unclaimed services (e.g., GitHub Pages, AWS S3, Heroku) susceptible to takeover.
18. **CVE Enrichment** (`cveEnrichment`)
    - Queries the NIST National Vulnerability Database (CVE API v2) for real CVEs based on the detected web technologies and their versions.
19. **Retire.js** (`retireJsChecker`)
    - Scans loaded JavaScript libraries against the Retire.js vulnerability database to find outdated, vulnerable client-side dependencies.
20. **API Discovery** (`apiDiscovery`)
    - Enumerates Swagger/OpenAPI specs, GraphQL endpoints, REST paths, WSDL/SOAP endpoints, JS-extracted API calls, and `robots.txt` paths.

## Platform Features
- **Real-Time Pipeline Tracking**: Live UI updates showing the status of each running module.
- **Aggregated Risk Scoring**: Automatically grades the target's security posture (A+ to F) based on finding severities.
- **Findings Triage UI**: Filterable, categorized findings dashboard with remediation advice.
- **Reporting**: Exports scan results into PDF, Markdown, and JSON formats.
- **Alerting Engine**: Configurable webhooks to notify external services (Slack, Discord) on critical findings.
