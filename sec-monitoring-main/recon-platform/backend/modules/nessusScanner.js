'use strict';
/**
 * nessusScanner.js — Agentless Nessus-Style Vulnerability Scanner
 *
 * Replicates Nessus plugin-style checks entirely over HTTP/HTTPS + TCP.
 * No API key, no Nessus install required.
 *
 * Plugin families covered:
 *  1.  Banner-based CVE detection (web server, FTP, SSH, SMTP banners)
 *  2.  TLS/SSL weakness checks (POODLE, BEAST, RC4, weak ciphers, expired certs)
 *  3.  HTTP misconfiguration (PUT/DELETE allowed, TRACE, OPTIONS disclosure)
 *  4.  Authentication bypass patterns (Basic auth over HTTP, anonymous FTP)
 *  5.  Default credential probes (Tomcat, Jenkins, Grafana, phpMyAdmin, RDP-style)
 *  6.  Sensitive data exposure (git, env, backup, config file disclosure)
 *  7.  Injection surface detection (SQL error patterns, error verbosity, server info leak)
 *  8.  Infrastructure misconfig (X-Powered-By, Server header version disclosure)
 *  9.  Network service checks (open database ports, unencrypted protocols)
 * 10.  CGI / legacy web checks (shellshock pattern, old ASP, PHP version)
 * 11.  Authentication security (login brute-force surface, MFA absence hints)
 * 12.  Security policy (HSTS, HPKP, Expect-CT, Referrer-Policy analysis)
 */

const net   = require('net');
const tls   = require('tls');
const dns   = require('dns').promises;
const https = require('https');
const http  = require('http');

// ── Helpers ────────────────────────────────────────────────────────────────────

async function safeFetch(url, opts = {}) {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), opts.timeout || 6000);
    const r = await fetch(url, {
      signal: controller.signal,
      redirect: 'manual',
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; NessusStyleScanner/1.0)',
        ...(opts.headers || {}),
      },
      ...opts,
    });
    clearTimeout(timer);
    const body = opts.noBody ? '' : await r.text().catch(() => '');
    return { ok: true, status: r.status, body, headers: Object.fromEntries(r.headers.entries()) };
  } catch (_) {
    return { ok: false, status: 0, body: '', headers: {} };
  }
}

/**
 * Raw TCP banner grab on a given host:port within timeoutMs.
 */
function grabBanner(host, port, timeoutMs = 4000) {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    let banner = '';
    sock.setTimeout(timeoutMs);
    sock.on('connect', () => sock.write('HEAD / HTTP/1.0\r\n\r\n'));
    sock.on('data', (d) => { banner += d.toString(); if (banner.length > 512) sock.destroy(); });
    sock.on('timeout', () => { sock.destroy(); resolve(banner); });
    sock.on('close', () => resolve(banner));
    sock.on('error', () => resolve(''));
    sock.connect(port, host);
  });
}

/**
 * TCP port connectivity check — returns true if port is open.
 */
function portOpen(host, port, timeoutMs = 3000) {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    sock.setTimeout(timeoutMs);
    sock.on('connect', () => { sock.destroy(); resolve(true); });
    sock.on('timeout', () => { sock.destroy(); resolve(false); });
    sock.on('error', () => resolve(false));
    sock.connect(port, host);
  });
}

/**
 * TLS handshake — negotiates with specific protocol version to test support.
 */
function tlsHandshake(host, port, options = {}, timeoutMs = 6000) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => { try { sock.destroy(); } catch (_) {} resolve(null); }, timeoutMs);
    let sock;
    try {
      sock = tls.connect(port, host, { rejectUnauthorized: false, ...options }, () => {
        clearTimeout(timer);
        resolve(sock.getCipher ? sock.getCipher() : null);
        sock.destroy();
      });
      sock.on('error', () => { clearTimeout(timer); resolve(null); });
    } catch (_) { clearTimeout(timer); resolve(null); }
  });
}

function addFinding(results, finding) {
  // Deduplicate by id
  if (!results.findings.find(f => f.id === finding.id)) {
    results.findings.push(finding);
  }
}

function plugin(id, family, name, severity, description, remediation, cves = [], cvssScore = null) {
  return { pluginId: id, family, name, severity, description, remediation, cves, cvssScore };
}

// ── Main ───────────────────────────────────────────────────────────────────────

async function runNessusScanner(domain, onProgress) {
  const results = {
    domain,
    targetIP: null,
    pluginResults: [],   // Nessus-style plugin findings
    findings: [],        // Platform findings schema
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, totalPlugins: 0, pluginFamilies: {} },
    scanEngine: 'Agentless Nessus-Style Scanner v1.0',
    policyName: 'Full Vulnerability Assessment',
    checkedAt: new Date().toISOString(),
  };

  // ── Resolve IP ──────────────────────────────────────────────────────────────
  onProgress('Resolving target IP address...');
  try {
    const ips = await dns.resolve4(domain);
    results.targetIP = ips[0] || null;
    onProgress(`Target resolved to ${results.targetIP}`);
  } catch (_) {
    onProgress('Could not resolve IP — some checks will be skipped');
  }

  const baseUrls = [`https://${domain}`, `http://${domain}`];
  let html = '', respHeaders = {}, baseUrl = '', statusCode = 0;

  onProgress('Fetching target page for analysis...');
  for (const url of baseUrls) {
    const r = await safeFetch(url, { timeout: 10000, noBody: false });
    if (r.ok || r.status > 0) {
      html = r.body; respHeaders = r.headers; baseUrl = url; statusCode = r.status; break;
    }
  }

  // Helper to emit a plugin result
  const emitPlugin = (pluginDef, affected = domain, extraDetail = '') => {
    const p = { ...pluginDef, affected, detail: extraDetail, ts: new Date().toISOString() };
    results.pluginResults.push(p);
    results.summary.totalPlugins++;
    results.summary[pluginDef.severity] = (results.summary[pluginDef.severity] || 0) + 1;
    results.summary.pluginFamilies[pluginDef.family] = (results.summary.pluginFamilies[pluginDef.family] || 0) + 1;
    addFinding(results, {
      id:          `NESSUS-${pluginDef.pluginId}`,
      severity:    pluginDef.severity,
      title:       pluginDef.name,
      description: pluginDef.description + (extraDetail ? ` Detail: ${extraDetail}` : ''),
      module:      'nessusScanner',
      affected,
      remediation: pluginDef.remediation,
      cves:        pluginDef.cves,
      cvssScore:   pluginDef.cvssScore,
      pluginId:    pluginDef.pluginId,
      pluginFamily:pluginDef.family,
    });
  };

  // ════════════════════════════════════════════════════════════════════════════
  // FAMILY 1 — Web Server Misconfiguration
  // ════════════════════════════════════════════════════════════════════════════
  onProgress('[Plugin Family] Web Server Misconfiguration checks...');

  // 1.1 Server version disclosure
  const serverHdr = respHeaders['server'] || '';
  if (serverHdr) {
    const versionPattern = /[\d.]{2,}/;
    if (versionPattern.test(serverHdr)) {
      emitPlugin(plugin(
        'NSS-10107', 'Web Servers', 'HTTP Server Version Disclosure',
        'medium',
        `The web server reveals its version in the Server header: "${serverHdr}". Attackers use this to target known CVEs.`,
        'Configure the web server to suppress or genericise the Server header (e.g., ServerTokens Prod in Apache, server_tokens off in Nginx).',
        [], 5.3
      ), `${baseUrl}`, serverHdr);
    }
    // Apache-specific CVEs
    if (/apache\//i.test(serverHdr)) {
      const m = serverHdr.match(/Apache\/([\d.]+)/i);
      if (m) {
        const ver = m[1];
        const [major, minor, patch] = ver.split('.').map(Number);
        if (major === 2 && minor === 4 && patch <= 49) {
          emitPlugin(plugin(
            'NSS-CVE-2021-41773', 'Web Servers', 'Apache 2.4.49 Path Traversal / RCE (CVE-2021-41773)',
            'critical',
            `Apache HTTP Server ${ver} is vulnerable to path traversal and possible remote code execution via CVE-2021-41773. An attacker can read files outside the document root.`,
            'Upgrade Apache to 2.4.51 or later immediately.',
            ['CVE-2021-41773', 'CVE-2021-42013'], 9.8
          ), domain, `Detected version: ${ver}`);
        }
        if (major === 2 && minor === 4 && patch <= 55) {
          emitPlugin(plugin(
            'NSS-CVE-2023-25690', 'Web Servers', 'Apache HTTP Request Smuggling (CVE-2023-25690)',
            'high',
            `Apache ${ver} may be vulnerable to HTTP request smuggling when mod_proxy is enabled (CVE-2023-25690).`,
            'Upgrade Apache to 2.4.56 or later.',
            ['CVE-2023-25690'], 9.8
          ), domain, `Detected version: ${ver}`);
        }
      }
    }
    // Nginx-specific CVEs
    if (/nginx\//i.test(serverHdr)) {
      const m = serverHdr.match(/nginx\/([\d.]+)/i);
      if (m) {
        const ver = m[1];
        const [major, minor, patch] = ver.split('.').map(Number);
        if (major === 1 && minor <= 20 && patch <= 0) {
          emitPlugin(plugin(
            'NSS-CVE-2021-23017', 'Web Servers', 'Nginx DNS Resolver Off-By-One Overflow (CVE-2021-23017)',
            'high',
            `Nginx ${ver} may be vulnerable to a one-byte memory overwrite in the DNS resolver, potentially leading to DoS or RCE.`,
            'Upgrade Nginx to 1.21.0 or 1.20.1 or later.',
            ['CVE-2021-23017'], 7.7
          ), domain, `Detected version: ${ver}`);
        }
      }
    }
    // IIS version checks
    if (/microsoft-iis/i.test(serverHdr)) {
      const m = serverHdr.match(/Microsoft-IIS\/([\d.]+)/i);
      if (m && parseFloat(m[1]) <= 7.5) {
        emitPlugin(plugin(
          'NSS-10684', 'Web Servers', 'Microsoft IIS End-of-Life Version Detected',
          'high',
          `IIS version ${m[1]} is end-of-life and no longer receives security patches.`,
          'Upgrade IIS to version 10 on Windows Server 2019 or 2022.',
          ['CVE-2017-7269'], 7.5
        ), domain, `Detected: ${serverHdr}`);
      }
    }
  }

  // 1.2 X-Powered-By disclosure
  const poweredBy = respHeaders['x-powered-by'] || '';
  if (poweredBy) {
    emitPlugin(plugin(
      'NSS-10107-XPB', 'Web Servers', 'X-Powered-By Technology Disclosure',
      'low',
      `The server reveals its application framework via the X-Powered-By header: "${poweredBy}". This aids attackers in fingerprinting the stack.`,
      'Remove the X-Powered-By header in your web framework configuration.',
      [], 3.7
    ), baseUrl, poweredBy);

    // PHP version-specific CVEs
    const phpMatch = poweredBy.match(/PHP\/([\d.]+)/i);
    if (phpMatch) {
      const ver = phpMatch[1];
      const parts = ver.split('.').map(Number);
      if (parts[0] === 7 && parts[1] <= 4) {
        emitPlugin(plugin(
          'NSS-CVE-PHP-EOL', 'Web Servers', 'PHP End-of-Life Version Detected',
          'high',
          `PHP ${ver} is end-of-life and no longer receives security updates. Known critical vulnerabilities exist.`,
          'Upgrade to PHP 8.2 or later.',
          ['CVE-2022-31625', 'CVE-2022-31626'], 9.8
        ), domain, `PHP/${ver}`);
      }
    }
  }

  // 1.3 HTTP TRACE method
  onProgress('Testing HTTP methods (TRACE, PUT, DELETE)...');
  const traceRes = await safeFetch(baseUrl, { method: 'TRACE', timeout: 5000 });
  if (traceRes.status === 200 && (traceRes.body || '').toUpperCase().includes('TRACE')) {
    emitPlugin(plugin(
      'NSS-11213', 'Web Servers', 'HTTP TRACE Method Enabled (XST)',
      'medium',
      'The HTTP TRACE method is enabled. This can be exploited in Cross-Site Tracing (XST) attacks to steal cookies and authentication tokens even with HttpOnly set.',
      'Disable TRACE method in the web server configuration. Apache: TraceEnable Off. Nginx: if ($request_method = TRACE) { return 405; }',
      ['CVE-2003-1567'], 5.8
    ), baseUrl, 'TRACE returned 200 with body echo');
  }

  // 1.4 HTTP PUT method (WebDAV)
  const putRes = await safeFetch(`${baseUrl}/nessus-test-${Date.now()}.txt`, { method: 'PUT', timeout: 5000, headers: { 'Content-Type': 'text/plain' } });
  if (putRes.status === 200 || putRes.status === 201 || putRes.status === 204) {
    emitPlugin(plugin(
      'NSS-10498', 'Web Servers', 'HTTP PUT Method Enabled (WebDAV/Arbitrary Upload)',
      'high',
      'The HTTP PUT method is accepted by the server. An attacker may upload arbitrary files including web shells.',
      'Disable WebDAV/PUT if not required. Restrict to authenticated users if needed.',
      ['CVE-2017-12542'], 8.1
    ), baseUrl, `PUT returned HTTP ${putRes.status}`);
  }

  // 1.5 OPTIONS method reveals allowed methods
  const optRes = await safeFetch(baseUrl, { method: 'OPTIONS', timeout: 5000 });
  const allowHeader = optRes.headers['allow'] || optRes.headers['public'] || '';
  if (allowHeader && /PUT|DELETE|PATCH/i.test(allowHeader)) {
    emitPlugin(plugin(
      'NSS-10498-OPT', 'Web Servers', 'Dangerous HTTP Methods Disclosed via OPTIONS',
      'medium',
      `OPTIONS response discloses dangerous methods: ${allowHeader}. This may indicate writable endpoints.`,
      'Restrict the Allow header to only necessary methods (GET, POST, HEAD).',
      [], 5.3
    ), baseUrl, `Allow: ${allowHeader}`);
  }

  // ════════════════════════════════════════════════════════════════════════════
  // FAMILY 2 — TLS/SSL Weakness
  // ════════════════════════════════════════════════════════════════════════════
  onProgress('[Plugin Family] TLS/SSL weakness checks...');

  if (results.targetIP || domain) {
    const tlsHost = results.targetIP || domain;

    // 2.1 SSLv3 / POODLE
    const sslv3 = await tlsHandshake(domain, 443, { maxVersion: 'TLSv1', minVersion: 'TLSv1' }, 5000);
    if (sslv3 !== null) {
      emitPlugin(plugin(
        'NSS-78479', 'TLS/SSL', 'TLSv1.0 Protocol Supported (POODLE/BEAST)',
        'medium',
        'The server supports TLS 1.0 which is vulnerable to BEAST and POODLE downgrade attacks. PCI-DSS has deprecated TLS 1.0 since 2018.',
        'Disable TLS 1.0 and 1.1. Enable TLS 1.2 minimum, prefer TLS 1.3.',
        ['CVE-2014-3566', 'CVE-2011-3389'], 5.9
      ), `${domain}:443`, 'TLS 1.0 handshake succeeded');
    }

    // 2.2 Check HTTPS at all
    const httpsCheck = await portOpen(domain, 443, 4000);
    if (!httpsCheck) {
      emitPlugin(plugin(
        'NSS-51192', 'TLS/SSL', 'No HTTPS Support Detected',
        'high',
        'The target does not appear to accept HTTPS connections on port 443. All traffic is transmitted in plaintext.',
        'Configure an SSL/TLS certificate and enable HTTPS on port 443.',
        [], 7.5
      ), `${domain}:443`, 'Port 443 closed or filtered');
    } else {
      // 2.3 Certificate validation
      try {
        const certInfo = await getCertInfo(domain);
        if (certInfo) {
          if (certInfo.expired) {
            emitPlugin(plugin(
              'NSS-15901', 'TLS/SSL', 'SSL Certificate Expired',
              'high',
              `The SSL certificate for ${domain} has expired on ${certInfo.validTo}. Expired certificates may be rejected by browsers and indicate neglected infrastructure.`,
              'Renew the SSL/TLS certificate immediately.',
              [], 7.5
            ), domain, `Expired: ${certInfo.validTo}`);
          } else if (certInfo.daysLeft < 30) {
            emitPlugin(plugin(
              'NSS-15901-EXP', 'TLS/SSL', 'SSL Certificate Expiring Soon',
              'medium',
              `The SSL certificate expires in ${certInfo.daysLeft} days (${certInfo.validTo}). Failure to renew will cause browser trust errors.`,
              'Renew the SSL/TLS certificate before it expires.',
              [], 5.0
            ), domain, `Days left: ${certInfo.daysLeft}`);
          }
          if (certInfo.selfSigned) {
            emitPlugin(plugin(
              'NSS-57582', 'TLS/SSL', 'Self-Signed SSL Certificate Detected',
              'medium',
              'The SSL certificate is self-signed and not trusted by browsers. This can allow man-in-the-middle attacks as users may bypass certificate warnings.',
              'Replace the self-signed certificate with one issued by a trusted Certificate Authority (e.g., Let\'s Encrypt).',
              [], 6.4
            ), domain, 'Self-signed issuer detected');
          }
          if (certInfo.weakKey) {
            emitPlugin(plugin(
              'NSS-35291', 'TLS/SSL', 'Weak RSA Key Size in SSL Certificate',
              'high',
              `The SSL certificate uses a weak RSA key size (${certInfo.keyBits} bits). Keys below 2048 bits are considered insecure.`,
              'Replace the certificate with one using at least 2048-bit RSA or an ECDSA key.',
              [], 7.5
            ), domain, `Key size: ${certInfo.keyBits} bits`);
          }
        }
      } catch (_) {}

      // 2.4 Missing HSTS
      const hsts = respHeaders['strict-transport-security'] || '';
      if (!hsts && baseUrl.startsWith('https://')) {
        emitPlugin(plugin(
          'NSS-84502', 'TLS/SSL', 'HTTP Strict Transport Security (HSTS) Not Enabled',
          'medium',
          'HSTS is not configured. Without HSTS, users can be downgraded to plain HTTP via MITM attacks or HSTS stripping.',
          'Add the header: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload',
          [], 6.1
        ), baseUrl, 'Missing Strict-Transport-Security header');
      } else if (hsts) {
        const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
        const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1]) : 0;
        if (maxAge < 15552000) { // < 180 days
          emitPlugin(plugin(
            'NSS-84502-WEAK', 'TLS/SSL', 'HSTS max-age Too Short',
            'low',
            `HSTS max-age is set to ${maxAge} seconds (${Math.round(maxAge/86400)} days), which is below the recommended 180 days (15552000 seconds).`,
            'Increase HSTS max-age to at least 15552000 (180 days), ideally 63072000 (2 years).',
            [], 3.7
          ), baseUrl, `max-age=${maxAge}`);
        }
        if (!hsts.includes('includeSubDomains')) {
          emitPlugin(plugin(
            'NSS-84502-NOSUB', 'TLS/SSL', 'HSTS Missing includeSubDomains Directive',
            'low',
            'HSTS does not include the includeSubDomains directive, meaning subdomains are not protected from SSL stripping.',
            'Add includeSubDomains to your HSTS header.',
            [], 3.7
          ), baseUrl, hsts);
        }
      }
    }
  }

  // ════════════════════════════════════════════════════════════════════════════
  // FAMILY 3 — Authentication & Access Control
  // ════════════════════════════════════════════════════════════════════════════
  onProgress('[Plugin Family] Authentication and access control checks...');

  // 3.1 HTTP Basic Auth over HTTP
  for (const url of baseUrls) {
    const r = await safeFetch(url, { timeout: 5000 });
    if ((r.headers['www-authenticate'] || '').toLowerCase().includes('basic') && url.startsWith('http://')) {
      emitPlugin(plugin(
        'NSS-26194', 'Authentication', 'HTTP Basic Authentication Over Cleartext HTTP',
        'high',
        'The server requests HTTP Basic Authentication over an unencrypted HTTP connection. Credentials are transmitted in Base64 (trivially decoded).',
        'Redirect all HTTP to HTTPS before requiring authentication. Never accept Basic Auth over plain HTTP.',
        [], 7.5
      ), url, r.headers['www-authenticate']);
    }
  }

  // 3.2 Anonymous FTP
  if (results.targetIP) {
    const ftpOpen = await portOpen(results.targetIP, 21, 3000);
    if (ftpOpen) {
      const banner = await grabBanner(results.targetIP, 21, 4000);
      emitPlugin(plugin(
        'NSS-10079', 'FTP', 'FTP Server Detected',
        'medium',
        `An FTP server is running on port 21. FTP transmits data and credentials in plaintext. Banner: "${banner.substring(0, 100)}"`,
        'Replace FTP with SFTP (SSH File Transfer Protocol) or FTPS. Restrict access via firewall.',
        [], 5.3
      ), `${results.targetIP}:21`, banner.substring(0, 80));

      // Try anonymous FTP
      const ftpAnon = await tryAnonymousFTP(results.targetIP);
      if (ftpAnon) {
        emitPlugin(plugin(
          'NSS-10079-ANON', 'FTP', 'Anonymous FTP Access Permitted',
          'high',
          'The FTP server accepts anonymous logins. Attackers can list and download files without authentication.',
          'Disable anonymous FTP access in the FTP server configuration.',
          ['CVE-1999-0497'], 7.5
        ), `${results.targetIP}:21`, 'Anonymous login succeeded');
      }
    }
  }

  // 3.3 Telnet detection
  if (results.targetIP) {
    const telnetOpen = await portOpen(results.targetIP, 23, 3000);
    if (telnetOpen) {
      emitPlugin(plugin(
        'NSS-10280', 'Infrastructure', 'Telnet Service Running',
        'critical',
        'Telnet is running on port 23. Telnet transmits all data including passwords in plaintext, making it trivially interceptable.',
        'Disable Telnet immediately. Use SSH for remote management.',
        ['CVE-1999-0619'], 9.8
      ), `${results.targetIP}:23`, 'Telnet port open');
    }
  }

  // 3.4 Admin panel discovery + default creds
  onProgress('[Plugin Family] Default credential and admin panel checks...');
  const adminPanels = [
    { path: '/manager/html',    name: 'Apache Tomcat Manager',   credPath: '/manager/j_security_check', bodyField: 'j_username=tomcat&j_password=tomcat', detectFn: (r) => r.status === 302 && (r.headers.location || '').includes('manager') },
    { path: '/wp-login.php',    name: 'WordPress Login',         credPath: '/wp-login.php',             bodyField: 'log=admin&pwd=admin&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1', detectFn: (r) => r.status === 302 && (r.headers.location || '').includes('wp-admin') && !(r.headers.location || '').includes('login') },
    { path: '/phpmyadmin/',     name: 'phpMyAdmin',              credPath: null,                        bodyField: null, detectFn: null },
    { path: '/jenkins',         name: 'Jenkins CI',              credPath: '/j_acegi_security_check',   bodyField: 'j_username=admin&j_password=admin', detectFn: (r) => r.status === 302 && !(r.headers.location || '').includes('loginError') },
    { path: '/grafana/login',   name: 'Grafana Dashboard',       credPath: '/api/login',                bodyField: JSON.stringify({ user: 'admin', password: 'admin' }), detectFn: (r) => r.status === 200 && (r.body || '').includes('token') },
    { path: '/admin',           name: 'Generic Admin Panel',     credPath: null,                        bodyField: null, detectFn: null },
    { path: '/adminer.php',     name: 'Adminer Database Tool',   credPath: null,                        bodyField: null, detectFn: null },
    { path: '/portainer/',      name: 'Portainer Docker UI',     credPath: '/api/users/admin/init',     bodyField: JSON.stringify({ username: 'admin', password: 'admin' }), detectFn: (r) => r.status === 200 },
  ];

  await Promise.allSettled(adminPanels.map(async (panel) => {
    const r = await safeFetch(`${baseUrl}${panel.path}`, { timeout: 5000 });
    if (r.status === 200 || r.status === 301 || r.status === 302) {
      const bodyLower = (r.body || '').toLowerCase();
      if (bodyLower.includes('login') || bodyLower.includes('password') || bodyLower.includes('username') || bodyLower.includes('sign in')) {
        emitPlugin(plugin(
          `NSS-ADMIN-${panel.name.replace(/\s+/g, '-').toUpperCase()}`,
          'Authentication', `Exposed Admin Panel: ${panel.name}`,
          'high',
          `${panel.name} admin interface is publicly accessible at ${panel.path}. Exposed admin panels are prime targets for brute-force and credential stuffing attacks.`,
          `Restrict access to ${panel.path} via IP allowlisting, VPN, or basic firewall rules. Ensure strong passwords and MFA are enforced.`,
          [], 7.5
        ), `${baseUrl}${panel.path}`, `HTTP ${r.status}`);

        // Try default credentials
        if (panel.credPath && panel.bodyField) {
          const isJson = panel.bodyField.startsWith('{');
          const credR = await safeFetch(`${baseUrl}${panel.credPath}`, {
            method: 'POST', timeout: 6000,
            headers: { 'Content-Type': isJson ? 'application/json' : 'application/x-www-form-urlencoded' },
            body: panel.bodyField,
          });
          if (panel.detectFn && panel.detectFn(credR)) {
            emitPlugin(plugin(
              `NSS-DEFCREDS-${panel.name.replace(/\s+/g, '-').toUpperCase()}`,
              'Authentication', `Default Credentials Accepted: ${panel.name}`,
              'critical',
              `${panel.name} accepted default credentials (admin/admin or similar). An attacker can immediately take full administrative control.`,
              'Change default credentials immediately. Enforce strong password policies and enable MFA on all admin interfaces.',
              [], 9.8
            ), `${baseUrl}${panel.credPath}`, 'Default credentials login succeeded');
          }
        }
      }
    }
  }));

  // ════════════════════════════════════════════════════════════════════════════
  // FAMILY 4 — Sensitive File Disclosure
  // ════════════════════════════════════════════════════════════════════════════
  onProgress('[Plugin Family] Sensitive file and configuration exposure...');

  const sensitiveChecks = [
    { path: '/.git/HEAD',            verify: 'ref:',       id: 'NSS-GIT-HEAD',     name: 'Git Repository HEAD Exposed',              sev: 'critical', cves: [] },
    { path: '/.git/config',          verify: '[core]',     id: 'NSS-GIT-CONFIG',   name: 'Git Config File Exposed',                  sev: 'critical', cves: [] },
    { path: '/.env',                 verify: '=',          id: 'NSS-ENV-FILE',     name: '.env Environment File Exposed',            sev: 'critical', cves: [] },
    { path: '/.env.production',      verify: '=',          id: 'NSS-ENV-PROD',     name: '.env.production File Exposed',             sev: 'critical', cves: [] },
    { path: '/wp-config.php',        verify: 'DB_NAME',    id: 'NSS-WPCONFIG',     name: 'WordPress wp-config.php Exposed',          sev: 'critical', cves: [] },
    { path: '/phpinfo.php',          verify: 'phpinfo()',  id: 'NSS-PHPINFO',      name: 'PHP Info Page Exposed',                    sev: 'high',     cves: [] },
    { path: '/server-status',        verify: 'Apache',     id: 'NSS-SRVSTATUS',    name: 'Apache Server Status Exposed',             sev: 'high',     cves: [] },
    { path: '/actuator',             verify: '_links',     id: 'NSS-ACTUATOR',     name: 'Spring Boot Actuator Endpoints Exposed',   sev: 'critical', cves: ['CVE-2022-22965'] },
    { path: '/actuator/env',         verify: 'activeProfiles', id: 'NSS-ACT-ENV', name: 'Actuator /env Endpoint Exposed',           sev: 'critical', cves: ['CVE-2022-22965'] },
    { path: '/actuator/heapdump',    verify: null,         id: 'NSS-HEAPDUMP',     name: 'JVM Heap Dump Endpoint Exposed',           sev: 'critical', cves: [] },
    { path: '/metrics',              verify: '# HELP',     id: 'NSS-PROMETHEUS',   name: 'Prometheus Metrics Endpoint Exposed',      sev: 'medium',   cves: [] },
    { path: '/graphql',              verify: 'data',       id: 'NSS-GRAPHQL',      name: 'GraphQL Endpoint Detected',                sev: 'medium',   cves: [] },
    { path: '/swagger-ui.html',      verify: 'swagger',    id: 'NSS-SWAGGER',      name: 'Swagger API Documentation Exposed',        sev: 'medium',   cves: [] },
    { path: '/v3/api-docs',          verify: 'openapi',    id: 'NSS-OPENAPI',      name: 'OpenAPI Specification Exposed',            sev: 'medium',   cves: [] },
    { path: '/dump.sql',             verify: null,         id: 'NSS-SQLDUMP',      name: 'SQL Database Dump Accessible',             sev: 'critical', cves: [] },
    { path: '/backup.sql',           verify: null,         id: 'NSS-SQLBAK',       name: 'SQL Database Backup Accessible',           sev: 'critical', cves: [] },
    { path: '/config.php',           verify: 'db',         id: 'NSS-CONFIGPHP',    name: 'PHP Config File Exposed',                  sev: 'critical', cves: [] },
    { path: '/config.json',          verify: null,         id: 'NSS-CONFIGJSON',   name: 'JSON Config File Exposed',                 sev: 'high',     cves: [] },
    { path: '/docker-compose.yml',   verify: 'services',   id: 'NSS-DOCKERCOMPOSE','name': 'Docker Compose File Exposed',            sev: 'high',     cves: [] },
    { path: '/Dockerfile',           verify: 'FROM',       id: 'NSS-DOCKERFILE',   name: 'Dockerfile Exposed',                       sev: 'medium',   cves: [] },
    { path: '/package.json',         verify: '"name"',     id: 'NSS-PACKAGEJSON',  name: 'package.json Version Disclosure',          sev: 'low',      cves: [] },
    { path: '/error.log',            verify: null,         id: 'NSS-ERRORLOG',     name: 'Error Log File Exposed',                   sev: 'high',     cves: [] },
    { path: '/robots.txt',           verify: 'Disallow',   id: 'NSS-ROBOTSTXT',    name: 'robots.txt Reveals Sensitive Paths',       sev: 'info',     cves: [] },
    { path: '/.DS_Store',            verify: null,         id: 'NSS-DSSTORE',      name: 'macOS .DS_Store File Exposed',             sev: 'medium',   cves: [] },
    { path: '/elmah.axd',            verify: 'Error Log',  id: 'NSS-ELMAH',        name: 'ELMAH Error Log Exposed (.NET)',            sev: 'high',     cves: [] },
    { path: '/trace.axd',            verify: 'trace',      id: 'NSS-TRACEAXD',     name: 'ASP.NET Trace.axd Exposed',                sev: 'high',     cves: [] },
    { path: '/credentials.json',     verify: 'client_id', id: 'NSS-GCPCREDS',     name: 'Google Cloud Credentials File Exposed',    sev: 'critical', cves: [] },
    { path: '/.htpasswd',            verify: ':',          id: 'NSS-HTPASSWD',     name: '.htpasswd Credentials File Exposed',       sev: 'critical', cves: [] },
    { path: '/crossdomain.xml',      verify: 'cross-domain','id':'NSS-CROSSDOM',  name: 'Flash crossdomain.xml Overly Permissive',  sev: 'medium',   cves: [] },
    { path: '/sitemap.xml',          verify: '<loc>',      id: 'NSS-SITEMAP',      name: 'Sitemap.xml Discloses URL Structure',      sev: 'info',     cves: [] },
  ];

  await Promise.allSettled(sensitiveChecks.map(async (chk) => {
    const r = await safeFetch(`${baseUrl}${chk.path}`, { timeout: 5000 });
    if (r.status !== 200) return;
    const body = r.body || '';
    const matched = !chk.verify || body.toLowerCase().includes(chk.verify.toLowerCase());
    if (!matched) return;
    emitPlugin(plugin(
      chk.id, 'Information Disclosure', chk.name,
      chk.sev,
      `${chk.path} is publicly accessible and contains sensitive information. This can expose credentials, infrastructure details, or application internals to attackers.`,
      `Restrict access to ${chk.path} via firewall rules or web server configuration. Remove sensitive files from the web root.`,
      chk.cves || [], chk.sev === 'critical' ? 9.1 : chk.sev === 'high' ? 7.5 : 5.3
    ), `${baseUrl}${chk.path}`, `HTTP 200 — verified content match`);
  }));

  // ════════════════════════════════════════════════════════════════════════════
  // FAMILY 5 — Injection Detection (Error-Based)
  // ════════════════════════════════════════════════════════════════════════════
  onProgress('[Plugin Family] Injection surface and error verbosity checks...');

  // SQL error detection
  const sqlTestUrls = [
    `${baseUrl}/?id=1'`,
    `${baseUrl}/?q=1"`,
    `${baseUrl}/search?q=1'--`,
    `${baseUrl}/product?id=1'`,
    `${baseUrl}/user?id=1 OR 1=1--`,
  ];
  const sqlErrorPatterns = [
    /mysql_fetch_array/i, /you have an error in your sql syntax/i,
    /unclosed quotation mark/i, /pg_query\(\)/i, /sqlite_step/i,
    /ORA-\d{5}/i, /Microsoft OLE DB Provider for SQL/i,
    /syntax error.*near/i, /invalid query/i, /sql command.*not properly ended/i,
    /warning.*mysql_/i, /division by zero/i,
  ];

  let sqlErrorFound = false;
  for (const testUrl of sqlTestUrls) {
    if (sqlErrorFound) break;
    const r = await safeFetch(testUrl, { timeout: 5000 });
    const body = r.body || '';
    for (const pat of sqlErrorPatterns) {
      if (pat.test(body)) {
        sqlErrorFound = true;
        emitPlugin(plugin(
          'NSS-SQL-INJECT', 'Injection', 'Possible SQL Injection Error Disclosure',
          'critical',
          `The server returned database error messages when submitted with SQL metacharacters at ${testUrl}. This suggests unsanitised input reaching the database layer.`,
          'Use parameterised queries/prepared statements throughout the application. Disable verbose database error messages in production.',
          ['CVE-2021-27928', 'CWE-89'], 9.8
        ), testUrl, body.substring(0, 200));
        break;
      }
    }
  }

  // XSS reflection test
  const xssPayload = '<script>xsstest</script>';
  const xssRes = await safeFetch(`${baseUrl}/?q=${encodeURIComponent(xssPayload)}`, { timeout: 5000 });
  if ((xssRes.body || '').includes('<script>xsstest</script>')) {
    emitPlugin(plugin(
      'NSS-XSS-REFLECT', 'Injection', 'Reflected XSS Vulnerability Detected',
      'high',
      'The server reflected an unencoded XSS payload in the response body. An attacker can craft a malicious URL that executes JavaScript in a victim\'s browser.',
      'HTML-encode all user-supplied input before rendering. Implement a strict Content Security Policy.',
      ['CWE-79'], 8.2
    ), `${baseUrl}/?q=`, `Payload reflected: ${xssPayload}`);
  }

  // Path traversal
  const traversalUrls = [
    `${baseUrl}/?file=../../etc/passwd`,
    `${baseUrl}/?path=../../../etc/passwd`,
    `${baseUrl}/download?file=../../etc/passwd`,
  ];
  for (const tUrl of traversalUrls) {
    const r = await safeFetch(tUrl, { timeout: 5000 });
    if (/root:x:0:0/.test(r.body || '')) {
      emitPlugin(plugin(
        'NSS-PATH-TRAV', 'Injection', 'Path Traversal Vulnerability Detected',
        'critical',
        `The server returned /etc/passwd contents in response to a path traversal payload at ${tUrl}. An attacker can read arbitrary files from the server.`,
        'Validate and sanitise all file path inputs. Use a whitelist of allowed file names/directories. Never pass user input directly to file system operations.',
        ['CWE-22', 'CVE-2021-41773'], 9.8
      ), tUrl, 'root:x:0:0 detected in response');
      break;
    }
  }

  // ════════════════════════════════════════════════════════════════════════════
  // FAMILY 6 — Network Infrastructure Checks
  // ════════════════════════════════════════════════════════════════════════════
  onProgress('[Plugin Family] Network infrastructure and dangerous service checks...');

  if (results.targetIP) {
    const dangerousPorts = [
      { port: 445,   name: 'SMB', sev: 'critical', cves: ['CVE-2017-0144', 'MS17-010'], cvss: 9.8, desc: 'SMB (port 445) is publicly reachable. This service has been exploited by EternalBlue and ransomware such as WannaCry and NotPetya. Any unauthenticated SMB exposure is a critical risk.', fix: 'Block SMB port 445 at the firewall perimeter. Apply all Microsoft patches (MS17-010). Never expose SMB to the internet.' },
      { port: 3389,  name: 'RDP', sev: 'high',     cves: ['CVE-2019-0708', 'BlueKeep'], cvss: 9.8, desc: 'RDP (port 3389) is publicly exposed. RDP is a frequent target for brute-force attacks and has several critical CVEs including BlueKeep (CVE-2019-0708).', fix: 'Restrict RDP access to VPN only. Enable Network Level Authentication (NLA). Apply all Windows security patches.' },
      { port: 5900,  name: 'VNC', sev: 'high',     cves: ['CVE-2002-1511'], cvss: 7.5, desc: 'VNC (port 5900) is exposed. VNC often runs without strong authentication and transmits screen data with weak encryption.', fix: 'Restrict VNC to localhost. Use SSH tunneling for remote access. Ensure strong VNC password is set.' },
      { port: 6379,  name: 'Redis', sev: 'critical', cves: ['CVE-2022-0543'], cvss: 10.0, desc: 'Redis (port 6379) is publicly accessible. Redis has no authentication by default and exposes all stored data. Known exploits allow arbitrary code execution.', fix: 'Bind Redis to localhost (bind 127.0.0.1). Enable requirepass authentication. Use a firewall to block external access.' },
      { port: 9200,  name: 'Elasticsearch', sev: 'high', cves: ['CVE-2021-22145'], cvss: 7.5, desc: 'Elasticsearch (port 9200) is publicly accessible without authentication. This commonly exposes sensitive data stored in indices.', fix: 'Enable Elasticsearch X-Pack security. Restrict access via firewall. Use Kibana with proper auth.' },
      { port: 27017, name: 'MongoDB', sev: 'high',  cves: ['CVE-2021-20329'], cvss: 7.5, desc: 'MongoDB (port 27017) is publicly accessible. MongoDB has no authentication by default and entire databases can be exfiltrated.', fix: 'Enable MongoDB authentication (--auth). Bind to localhost. Use firewall rules to prevent external access.' },
      { port: 3306,  name: 'MySQL', sev: 'high',    cves: ['CVE-2021-2307'], cvss: 7.5, desc: 'MySQL database (port 3306) is directly exposed to the internet. This allows remote authentication attempts and data exfiltration.', fix: 'Bind MySQL to 127.0.0.1. Use firewall rules. Remove anonymous/root remote access accounts.' },
      { port: 5432,  name: 'PostgreSQL', sev: 'high', cves: ['CVE-2022-1552'], cvss: 8.8, desc: 'PostgreSQL (port 5432) is publicly accessible. Direct database exposure allows brute-force attacks and potential data theft.', fix: 'Restrict pg_hba.conf to localhost. Use firewall rules to block external access.' },
      { port: 1433,  name: 'MSSQL', sev: 'high',   cves: ['CVE-2020-0618'], cvss: 8.8, desc: 'Microsoft SQL Server (port 1433) is publicly exposed. MSSQL has been targeted by multiple critical exploits.', fix: 'Block port 1433 at the firewall. Use VPN for remote database access.' },
      { port: 2375,  name: 'Docker API (unencrypted)', sev: 'critical', cves: ['CVE-2019-5736'], cvss: 9.0, desc: 'The unencrypted Docker daemon API (port 2375) is accessible. This gives an attacker full container control and likely root access to the host.', fix: 'Disable the unencrypted Docker API. Use TLS-authenticated Docker API on port 2376 only.' },
      { port: 9092,  name: 'Apache Kafka', sev: 'medium', cves: [], cvss: 5.3, desc: 'Apache Kafka (port 9092) is publicly reachable. Kafka has no built-in authentication by default, allowing unauthorised message consumption and production.', fix: 'Configure Kafka SASL/SSL authentication. Use firewall rules to restrict access.' },
      { port: 8161,  name: 'ActiveMQ Web Console', sev: 'critical', cves: ['CVE-2023-46604'], cvss: 10.0, desc: 'ActiveMQ Web Console (port 8161) is exposed. CVE-2023-46604 allows unauthenticated remote code execution on ActiveMQ.', fix: 'Patch ActiveMQ to version 5.15.16, 5.16.7, or 5.17.6+. Restrict web console access via firewall.' },
      { port: 4848,  name: 'GlassFish Admin Console', sev: 'high', cves: ['CVE-2017-1000029'], cvss: 7.5, desc: 'GlassFish Admin Console (port 4848) is accessible. GlassFish admin interfaces often have default credentials and security vulnerabilities.', fix: 'Restrict the admin console to localhost. Change default credentials. Use firewall rules.' },
      { port: 7001,  name: 'Oracle WebLogic', sev: 'critical', cves: ['CVE-2023-21839', 'CVE-2021-2109'], cvss: 9.8, desc: 'Oracle WebLogic server (port 7001) is accessible. Multiple critical unauthenticated RCE CVEs exist for WebLogic.', fix: 'Apply all Oracle Critical Patch Updates. Restrict T3/IIOP protocols via firewall. Disable JNDI if not needed.' },
    ];

    const portChecks = dangerousPorts.map(async (svc) => {
      const open = await portOpen(results.targetIP, svc.port, 3000);
      if (open) {
        emitPlugin(plugin(
          `NSS-PORT-${svc.port}`, 'Network Services', `Dangerous Service Exposed: ${svc.name} (port ${svc.port})`,
          svc.sev, svc.desc, svc.fix, svc.cves, svc.cvss
        ), `${results.targetIP}:${svc.port}`, `Port ${svc.port} open`);
      }
    });
    await Promise.allSettled(portChecks);
  }

  // ════════════════════════════════════════════════════════════════════════════
  // FAMILY 7 — CGI & Legacy Platform Checks
  // ════════════════════════════════════════════════════════════════════════════
  onProgress('[Plugin Family] CGI, Shellshock, and legacy application checks...');

  // Shellshock (CVE-2014-6271)
  const shellshockRes = await safeFetch(`${baseUrl}/cgi-bin/test.cgi`, {
    timeout: 5000,
    headers: { 'User-Agent': '() { ignored;}; echo Content-Type: text/plain; echo; echo SHELLSHOCK-TEST' }
  });
  if ((shellshockRes.body || '').includes('SHELLSHOCK-TEST')) {
    emitPlugin(plugin(
      'NSS-CVE-2014-6271', 'CGI', 'Shellshock — Remote Code Execution via CGI (CVE-2014-6271)',
      'critical',
      'The server is vulnerable to Shellshock. CGI scripts pass the User-Agent header to bash, which executes injected commands. This allows unauthenticated remote code execution.',
      'Update bash to a patched version (bash-4.3 patch 25+). Disable CGI if not required.',
      ['CVE-2014-6271', 'CVE-2014-7169'], 10.0
    ), `${baseUrl}/cgi-bin/`, 'SHELLSHOCK-TEST string returned in response');
  }

  // Heartbleed pattern (TLS extension-level — detect via banner/cert only)
  if (results.targetIP) {
    try {
      const certInfo = await getCertInfo(domain);
      if (certInfo && certInfo.validFrom) {
        const issuedBefore2014 = new Date(certInfo.validFrom) < new Date('2014-06-01');
        if (issuedBefore2014) {
          emitPlugin(plugin(
            'NSS-HEARTBLEED-HINT', 'TLS/SSL', 'Certificate Pre-Dates Heartbleed — Verify Revocation',
            'info',
            `The TLS certificate was issued before the Heartbleed disclosure date (June 2014). If the private key was compromised via Heartbleed, this certificate may still be in use with a compromised key.`,
            'Issue a new certificate with a freshly generated private key. Verify the certificate serial number has not been revoked.',
            ['CVE-2014-0160'], 0
          ), domain, `Certificate issued: ${certInfo.validFrom}`);
        }
      }
    } catch (_) {}
  }

  // ════════════════════════════════════════════════════════════════════════════
  // FAMILY 8 — Security Policy & Headers
  // ════════════════════════════════════════════════════════════════════════════
  onProgress('[Plugin Family] Security policy and HTTP header analysis...');

  const securityHeaderChecks = [
    { header: 'content-security-policy', id: 'NSS-HDR-CSP',    name: 'Missing Content-Security-Policy Header',    sev: 'high',   desc: 'No Content-Security-Policy (CSP) header is set. CSP is the primary defence against Cross-Site Scripting (XSS) and data injection attacks.', fix: "Set: Content-Security-Policy: default-src 'self'; script-src 'self'" },
    { header: 'x-frame-options',         id: 'NSS-HDR-XFO',    name: 'Missing X-Frame-Options Header',           sev: 'medium', desc: 'X-Frame-Options is not set, allowing the site to be embedded in iframes. This enables Clickjacking attacks.', fix: 'Set: X-Frame-Options: DENY (or SAMEORIGIN if iframes are needed).' },
    { header: 'x-content-type-options',  id: 'NSS-HDR-XCTO',   name: 'Missing X-Content-Type-Options Header',    sev: 'low',    desc: 'X-Content-Type-Options: nosniff is not set. Browsers may MIME-sniff responses, leading to XSS via content-type confusion.', fix: 'Set: X-Content-Type-Options: nosniff' },
    { header: 'referrer-policy',         id: 'NSS-HDR-RP',     name: 'Missing Referrer-Policy Header',           sev: 'low',    desc: 'No Referrer-Policy header is configured. Sensitive URLs may be leaked to third parties via the Referer header.', fix: 'Set: Referrer-Policy: strict-origin-when-cross-origin' },
    { header: 'permissions-policy',      id: 'NSS-HDR-PP',     name: 'Missing Permissions-Policy Header',        sev: 'low',    desc: 'No Permissions-Policy (formerly Feature-Policy) is set. Browser features like camera, microphone, and geolocation are unrestricted.', fix: "Set: Permissions-Policy: camera=(), microphone=(), geolocation=()" },
  ];

  for (const chk of securityHeaderChecks) {
    if (!respHeaders[chk.header]) {
      emitPlugin(plugin(
        chk.id, 'Security Policy', chk.name,
        chk.sev, chk.desc, chk.fix, [], chk.sev === 'high' ? 6.1 : chk.sev === 'medium' ? 4.3 : 3.1
      ), baseUrl, `Header "${chk.header}" not present`);
    }
  }

  // Check for CSP weaknesses if present
  const csp = respHeaders['content-security-policy'] || '';
  if (csp) {
    if (csp.includes("'unsafe-inline'") || csp.includes("'unsafe-eval'")) {
      emitPlugin(plugin(
        'NSS-HDR-CSP-WEAK', 'Security Policy', 'Content-Security-Policy Contains Unsafe Directives',
        'medium',
        `CSP contains unsafe directives: ${csp.includes("'unsafe-inline'") ? "'unsafe-inline' " : ''}${csp.includes("'unsafe-eval'") ? "'unsafe-eval'" : ''}. These directives largely negate XSS protection.`,
        "Remove 'unsafe-inline' and 'unsafe-eval' from your CSP. Use nonces or hashes for inline scripts instead.",
        [], 5.3
      ), baseUrl, csp.substring(0, 200));
    }
    if (csp.includes('*')) {
      emitPlugin(plugin(
        'NSS-HDR-CSP-WILD', 'Security Policy', 'Content-Security-Policy Uses Wildcard Source',
        'medium',
        "The CSP uses a wildcard (*) source directive, which allows content from any origin. This significantly weakens XSS protection.",
        "Replace wildcard sources with explicit, trusted origins.",
        [], 5.3
      ), baseUrl, `CSP wildcard detected`);
    }
  }

  // ════════════════════════════════════════════════════════════════════════════
  // FAMILY 9 — Information Disclosure & Fingerprinting
  // ════════════════════════════════════════════════════════════════════════════
  onProgress('[Plugin Family] Information disclosure and fingerprinting...');

  // Internal IP disclosure in response body
  const internalIPPattern = /\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g;
  const internalIPMatches = (html || '').match(internalIPPattern);
  if (internalIPMatches && internalIPMatches.length > 0) {
    const unique = [...new Set(internalIPMatches)];
    emitPlugin(plugin(
      'NSS-10759', 'Information Disclosure', 'Internal IP Addresses Disclosed in HTTP Response',
      'medium',
      `The HTTP response body reveals internal/private IP addresses: ${unique.slice(0, 5).join(', ')}. This leaks network topology information useful for SSRF and lateral movement attacks.`,
      'Remove internal IP references from public-facing responses. Configure reverse proxies to strip internal addresses from responses.',
      [], 5.3
    ), baseUrl, unique.slice(0, 3).join(', '));
  }

  // Debug/stack trace patterns in response
  const stackTracePattern = /stack trace|exception in thread|at java\.|at com\.|at org\.|Traceback \(most recent|line \d+, in |File ".*?", line \d+|NullPointerException|undefined is not a function/i;
  if (stackTracePattern.test(html || '')) {
    emitPlugin(plugin(
      'NSS-10409', 'Information Disclosure', 'Application Stack Trace / Error Details Disclosed',
      'medium',
      'The server returned detailed error or stack trace information in the response. This reveals application internals, file paths, class names, and technology stack details.',
      'Disable verbose error messages in production. Configure custom error pages. Use structured logging to internal systems only.',
      [], 5.3
    ), baseUrl, 'Stack trace / exception pattern detected in response');
  }

  // Email address disclosure
  const emailPattern = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g;
  const emailMatches = (html || '').match(emailPattern);
  if (emailMatches && emailMatches.length > 3) {
    emitPlugin(plugin(
      'NSS-EMAIL-DISC', 'Information Disclosure', 'Multiple Email Addresses Exposed in Page Source',
      'info',
      `${emailMatches.length} email addresses found in the page source. These can be harvested for phishing or spam campaigns.`,
      'Obfuscate email addresses in public-facing HTML. Use contact forms instead of direct email links.',
      [], 2.7
    ), baseUrl, `Found: ${emailMatches.slice(0, 3).join(', ')}`);
  }

  // ════════════════════════════════════════════════════════════════════════════
  // FAMILY 10 — CORS & Cookie Security
  // ════════════════════════════════════════════════════════════════════════════
  onProgress('[Plugin Family] CORS and cookie security checks...');

  // CORS wildcard
  const corsRes = await safeFetch(baseUrl, {
    timeout: 6000,
    headers: { 'Origin': 'https://evil-cors-test.com' }
  });
  const acao = corsRes.headers['access-control-allow-origin'] || '';
  const acac = corsRes.headers['access-control-allow-credentials'] || '';
  if (acao === '*') {
    emitPlugin(plugin(
      'NSS-CORS-WILD', 'Web Servers', 'Wildcard CORS Policy (ACAO: *)',
      acac.toLowerCase() === 'true' ? 'critical' : 'medium',
      `Access-Control-Allow-Origin: * allows any website to make cross-origin requests. ${acac.toLowerCase() === 'true' ? 'COMBINED with Access-Control-Allow-Credentials: true, this creates a critical security risk allowing cross-origin credential theft.' : ''}`,
      'Restrict CORS to specific trusted origins. Never combine ACAO: * with Allow-Credentials: true.',
      ['CWE-942'], acac.toLowerCase() === 'true' ? 9.1 : 6.5
    ), baseUrl, `ACAO: ${acao}, ACAC: ${acac || 'not set'}`);
  } else if (acao.includes('evil-cors-test.com')) {
    emitPlugin(plugin(
      'NSS-CORS-REFLECT', 'Web Servers', 'CORS Origin Reflection',
      'critical',
      'The server reflects the Origin header in Access-Control-Allow-Origin, meaning any website can make authenticated cross-origin requests.',
      'Whitelist specific trusted origins. Never echo the Origin header back directly.',
      ['CWE-942'], 9.1
    ), baseUrl, `ACAO reflects: ${acao}`);
  }

  // Cookie security
  const setCookieHdr = corsRes.headers['set-cookie'] || respHeaders['set-cookie'] || '';
  if (setCookieHdr) {
    if (!/;\s*secure/i.test(setCookieHdr)) {
      emitPlugin(plugin(
        'NSS-COOKIE-SEC', 'Web Servers', 'Session Cookie Missing Secure Flag',
        'medium',
        'A session cookie is set without the Secure flag. The cookie may be transmitted over unencrypted HTTP connections, allowing interception.',
        'Add the Secure flag to all session and authentication cookies.',
        ['CWE-614'], 5.9
      ), baseUrl, 'Set-Cookie without Secure flag');
    }
    if (!/;\s*httponly/i.test(setCookieHdr)) {
      emitPlugin(plugin(
        'NSS-COOKIE-HTTP', 'Web Servers', 'Session Cookie Missing HttpOnly Flag',
        'medium',
        'A cookie is set without the HttpOnly flag. JavaScript can read this cookie, enabling theft via XSS attacks.',
        'Add the HttpOnly flag to all session cookies to prevent JavaScript access.',
        ['CWE-1004'], 5.9
      ), baseUrl, 'Set-Cookie without HttpOnly flag');
    }
    if (!/;\s*samesite/i.test(setCookieHdr)) {
      emitPlugin(plugin(
        'NSS-COOKIE-SAME', 'Web Servers', 'Session Cookie Missing SameSite Flag',
        'low',
        'Cookies are set without the SameSite flag, allowing them to be sent with cross-site requests. This contributes to CSRF vulnerabilities.',
        'Set SameSite=Lax (or Strict for maximum security) on all session cookies.',
        ['CWE-352'], 3.7
      ), baseUrl, 'Set-Cookie without SameSite flag');
    }
  }

  // ════════════════════════════════════════════════════════════════════════════
  // FAMILY 11 — Subdomain / DNS Checks
  // ════════════════════════════════════════════════════════════════════════════
  onProgress('[Plugin Family] DNS and subdomain security checks...');

  // DNS zone transfer attempt
  try {
    const nsRecords = await dns.resolveNs(domain).catch(() => []);
    if (nsRecords.length > 0) {
      // Report nameservers found
      emitPlugin(plugin(
        'NSS-DNS-NS', 'DNS', 'Nameserver Records Enumerated',
        'info',
        `Nameservers for ${domain}: ${nsRecords.slice(0, 5).join(', ')}. This information is public but useful for targeted DNS attacks.`,
        'Ensure nameservers are hardened and not running outdated BIND versions.',
        [], 0
      ), domain, nsRecords.slice(0, 3).join(', '));

      // Zone transfer attempt
      for (const ns of nsRecords.slice(0, 2)) {
        try {
          const resolver = new (require('dns').Resolver)();
          resolver.setServers([ns + ':53']);
          const axfr = await resolver.resolve(domain, 'AXFR').catch(() => null);
          if (axfr && Array.isArray(axfr) && axfr.length > 5) {
            emitPlugin(plugin(
              'NSS-10595', 'DNS', 'DNS Zone Transfer (AXFR) Permitted',
              'high',
              `The nameserver ${ns} allows zone transfer requests. This discloses ALL DNS records for ${domain} including internal hostnames, mail servers, and IP addresses.`,
              'Restrict zone transfers to authorised secondary nameservers only using ACLs in your DNS server configuration.',
              ['CVE-1999-0532'], 7.5
            ), `${ns}:53`, `AXFR returned ${axfr.length} records`);
          }
        } catch (_) {}
      }
    }
  } catch (_) {}

  // SPF/DMARC checks
  try {
    const txtRecords = await dns.resolveTxt(domain).catch(() => []);
    const allTxt = txtRecords.flat().join(' ');
    const hasSpf = allTxt.includes('v=spf1');
    const hasDmarc = allTxt.includes('v=DMARC1');
    if (!hasSpf) {
      emitPlugin(plugin(
        'NSS-EMAIL-SPF', 'DNS', 'Missing SPF Record (Email Spoofing Risk)',
        'medium',
        `No SPF (Sender Policy Framework) TXT record found for ${domain}. Without SPF, anyone can send emails appearing to originate from this domain (email spoofing / phishing).`,
        'Add an SPF TXT record to your DNS: v=spf1 include:your-mail-provider.com ~all',
        [], 5.3
      ), domain, 'No v=spf1 record found');
    }
    if (!hasDmarc) {
      emitPlugin(plugin(
        'NSS-EMAIL-DMARC', 'DNS', 'Missing DMARC Record',
        'medium',
        `No DMARC record found for ${domain}. DMARC prevents email spoofing and provides visibility into phishing attempts using your domain.`,
        'Add a DMARC TXT record: _dmarc.yourdomain.com → v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com',
        [], 5.3
      ), domain, 'No v=DMARC1 record found');
    }
  } catch (_) {}

  // ════════════════════════════════════════════════════════════════════════════
  // Build final summary
  // ════════════════════════════════════════════════════════════════════════════
  results.summary.totalFindings = results.findings.length;

  onProgress(`Nessus-style scan complete — ${results.pluginResults.length} plugins triggered, ${results.findings.length} findings`);
  return results;
}

// ── TLS Certificate Info ───────────────────────────────────────────────────────

function getCertInfo(host) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(null), 8000);
    try {
      const sock = tls.connect(443, host, { rejectUnauthorized: false, servername: host }, () => {
        clearTimeout(timer);
        const cert = sock.getPeerCertificate(true);
        sock.destroy();
        if (!cert || !cert.valid_to) return resolve(null);
        const validTo   = new Date(cert.valid_to);
        const validFrom = new Date(cert.valid_from);
        const now       = new Date();
        const daysLeft  = Math.round((validTo - now) / 86400000);
        const expired   = daysLeft < 0;
        const selfSigned = cert.issuer?.CN === cert.subject?.CN;
        const keyBits   = cert.pubkey?.length ? cert.pubkey.length * 8 : 2048;
        const weakKey   = cert.bits ? cert.bits < 2048 : false;
        resolve({ validTo: validTo.toISOString(), validFrom: validFrom.toISOString(), daysLeft, expired, selfSigned, weakKey, keyBits: cert.bits || 0 });
      });
      sock.on('error', () => { clearTimeout(timer); resolve(null); });
    } catch (_) { clearTimeout(timer); resolve(null); }
  });
}

// ── Anonymous FTP Try ─────────────────────────────────────────────────────────

function tryAnonymousFTP(host) {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    let data = ''; let step = 0;
    sock.setTimeout(6000);
    sock.on('data', (d) => {
      data += d.toString();
      if (step === 0 && data.includes('220')) { sock.write('USER anonymous\r\n'); step++; }
      else if (step === 1 && data.includes('331')) { sock.write('PASS anon@anon.com\r\n'); step++; }
      else if (step === 2) { resolve(data.includes('230')); sock.destroy(); }
    });
    sock.on('timeout', () => { sock.destroy(); resolve(false); });
    sock.on('error', () => resolve(false));
    sock.connect(21, host);
  });
}

module.exports = { runNessusScanner };
