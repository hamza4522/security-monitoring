# Security Assessment Tools Comparison

This document provides a comparison of open-source capabilities implemented in this security assessment platform, the standalone open-source tools they replicate or integrate with, and commercial/paid alternatives that offer similar features.

## Module & Tool Comparison Matrix

| Capability / Module | Internal Module | Open-Source Standalone Substitutes | Commercial / Paid Alternatives | Commercial Pricing Examples |
|-------------------|------------------|------------------------------------|--------------------------------|-----------------------------|
| **Asset Discovery & Subdomains** | `assetDiscovery` | Sublist3r, Amass, crt.sh, Findomain | SecurityTrails, Censys, Shodan Enterprise | SecurityTrails (Starts ~$100/mo), Censys Enterprise (Custom, high) |
| **Port Scanning** | `portScan` | Nmap, Masscan, Naabu, RustScan | Nessus Pro, Tenable.io | Nessus Pro (~$4,000/yr) |
| **Vulnerability Scanning** | `vulnAssessment`, `nucleiChecks` | Nuclei, OpenVAS, Nikto | Nessus, Qualys, Rapid7 InsightVM | Qualys VMDR (~$2,000+/yr), Rapid7 (Custom) |
| **Web Tech Fingerprinting** | `webTechFingerprint` | Wappalyzer (CLI), WhatWeb | BuiltWith, Wappalyzer Pro | BuiltWith Pro ($295+/mo) |
| **WAF / CDN Detection** | `wafDetector` | WafW00f, WhatWaf | Imperva AppSec, Cloudflare Security Analytics | Included in enterprise WAF subscriptions |
| **Web Attacks (DAST)** | `wapitiscan` | Wapiti, OWASP ZAP, SQLMap, Arachni | Burp Suite Professional, Acunetix, Invicti | Burp Pro (~$450/yr), Acunetix ($4,500+/yr) |
| **JS Secrets & Hardcoded Keys** | `jsSecretScanner` | TruffleHog, GitLeaks, SecretScanner | GitHub Advanced Security, Spectral, GitGuardian | GitGuardian (Custom enterprise), GitHub Adv Sec ($49/user/mo) |
| **API Discovery** | `apiDiscovery` | Kiterunner, ffuf, Gobuster | Postman Enterprise, Noname Security | Noname Security (Enterprise pricing) |
| **CVE Enrichment & Tech Vulns** | `cveEnrichment`, `retireJsChecker` | Retire.js, Vulners, Dependency-Check | Snyk, Sonatype Nexus Lifecycle | Snyk Team ($25/user/mo to Enterprise) |
| **CMS Vulnerability Scan** | `cmsVulnScan` | WPScan, Droopescan, CMSeeK | WPScan Enterprise API, Sucuri | WPScan API (Varies, up to $200+/mo for commercial) |
| **Subdomain Takeover** | `subdomainTakeover` | SubOver, takeover, tko-subs | Detectify, Bugcrowd/HackerOne ASM | Detectify (Custom enterprise pricing) |
| **SSL/TLS Auditing** | `sslScan` | SSLyze, TestSSL.sh | SSL Labs (Qualys), Digicert Cert Central | Mostly included in general VM or cert management platforms |
| **DNS & Email Auth (SPF/DMARC)** | `dnsAssessment` | DNSRecon, checkdmarc | Valimail, Proofpoint | Valimail Defend (Enterprise tier) |
| **Subresource Integrity (SRI) / Cookies** | `sriScanner`, `cookieSecurityScanner` | OWASP ZAP (Passive scan), Lighthouse | Burp Suite Professional | Burp Pro (~$450/yr) |

## Key Insights

1. **Consolidation**: By aggregating these open-source tools or implementing their core logic internally, this platform reduces the need to maintain and parse outputs from 15+ disparate CLI tools.
2. **Cost Savings**: A comprehensive commercial External Attack Surface Management (EASM) and Dynamic Application Security Testing (DAST) stack covering these areas typically costs upwards of **$10,000 to $25,000+ per year**. 
3. **Continuous Monitoring**: Commercial tools often gate continuous scanning behind higher tiers. Open-source platforms like this can be scheduled via cron or CI/CD pipelines at zero marginal software cost.

## Links to Mentioned Open-Source Tools
- [Nmap](https://nmap.org/)
- [Nuclei](https://nuclei.projectdiscovery.io/)
- [Amass](https://github.com/owasp-amass/amass)
- [Sublist3r](https://github.com/aboul3la/Sublist3r)
- [OWASP ZAP](https://www.zaproxy.org/)
- [Wapiti](https://wapiti.sourceforge.io/)
- [TruffleHog](https://github.com/trufflesecurity/trufflehog)
- [Retire.js](https://retirejs.github.io/retire.js/)
- [WPScan](https://wpscan.com/wordpress-security-scanner)
- [WafW00f](https://github.com/EnableSecurity/wafw00f)
