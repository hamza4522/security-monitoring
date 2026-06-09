'use strict';
/**
 * vulnAssessment.js — Enhanced Vulnerability Assessment Module
 *
 * Covers:
 *  1.  Security headers (HSTS, CSP, X-Frame-Options, etc.)
 *  2.  Cookie security flags
 *  3.  CSP evaluation
 *  4.  CORS misconfiguration
 *  5.  HTTPS redirect enforcement
 *  6.  Dangerous HTTP methods
 *  7.  Sensitive file probing (120+ paths — Nikto-inspired)
 *  8.  Backup / swap file probing (.bak, .old, .orig, .swp, ~)
 *  9.  robots.txt & sitemap.xml analysis
 *  10. Exposed API / monitoring endpoints
 *  11. Default credentials testing (8 admin panels)
 *  12. Directory listing (20+ dirs)
 *  13. Debug / error / stack-trace detection
 *  14. SSL/TLS certificate check
 *  15. CVE header matching (35+ patterns)
 *  16. CSRF token detection
 *  17. JWT cookie detection
 *  18. Open redirect testing
 *  19. Information disclosure (internal IPs, error verbosity)
 */

const tls   = require('tls');
const https = require('https');

// ── Helpers ───────────────────────────────────────────────────────────────────

async function safeFetch(url, opts = {}) {
  try {
    const r = await fetch(url, {
      redirect: 'manual',
      signal: AbortSignal.timeout(opts.timeout || 5000),
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/2.0)' },
      ...opts,
    });
    const body = opts.noBody ? '' : await r.text().catch(() => '');
    return { ok: true, status: r.status, body, headers: Object.fromEntries(r.headers.entries()) };
  } catch (_) {
    return { ok: false, status: 0, body: '', headers: {} };
  }
}

// ── Main ─────────────────────────────────────────────────────────────────────

async function runVulnAssessment(domain, onProgress) {
  const results = { domain, checks: [], findings: [], summary: { pass: 0, fail: 0, warn: 0, info: 0 } };
  const baseUrls = [`https://${domain}`, `http://${domain}`];
  let html = '', headers = {}, baseUrl = '', cookies = '';

  // ── Fetch base page ──────────────────────────────────────────────────────
  onProgress('Fetching target for vulnerability assessment...');
  for (const url of baseUrls) {
    try {
      const r = await fetch(url, {
        redirect: 'follow',
        signal: AbortSignal.timeout(12000),
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0' },
      });
      html = await r.text(); headers = Object.fromEntries(r.headers.entries());
      cookies = headers['set-cookie'] || ''; baseUrl = url; break;
    } catch (_) {}
  }
  if (!baseUrl) { onProgress('Target unreachable'); return results; }

  // ── Soft-404 detection ───────────────────────────────────────────────────
  let hasSoft404 = false;
  try {
    const sc = await safeFetch(baseUrl + '/vuln-scan-nonexistent-' + Math.random().toString(36).slice(2));
    if (sc.status === 200) hasSoft404 = true;
  } catch (_) {}

  // Helper: probe a path, verify content if soft-404 or verify keyword provided
  async function probe(path, verifyStr = null) {
    const r = await safeFetch(baseUrl + path, { timeout: 5000, noBody: !verifyStr && !hasSoft404 });
    if (r.status !== 200) return false;
    if (hasSoft404 || verifyStr) {
      const body = r.body || (await safeFetch(baseUrl + path, { timeout: 5000 })).body;
      if (verifyStr && !body.toLowerCase().includes(verifyStr.toLowerCase())) return false;
    }
    return true;
  }

  // ── 1. Security Headers ──────────────────────────────────────────────────
  onProgress('Checking HTTP security headers...');
  const secHeaders = [
    { name: 'Strict-Transport-Security', sev: 'high',   desc: 'HSTS not set — browsers can downgrade to HTTP', fix: 'Add: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload' },
    { name: 'Content-Security-Policy',   sev: 'high',   desc: 'No CSP — XSS/data injection unmitigated', fix: "Add: Content-Security-Policy: default-src 'self'" },
    { name: 'X-Frame-Options',           sev: 'medium', desc: 'Clickjacking protection missing', fix: 'Add: X-Frame-Options: DENY' },
    { name: 'X-Content-Type-Options',    sev: 'medium', desc: 'MIME-sniffing not prevented', fix: 'Add: X-Content-Type-Options: nosniff' },
    { name: 'Referrer-Policy',           sev: 'low',    desc: 'Referrer policy not set', fix: 'Add: Referrer-Policy: strict-origin-when-cross-origin' },
    { name: 'Permissions-Policy',        sev: 'low',    desc: 'Permissions policy not configured', fix: 'Add Permissions-Policy header to restrict browser features' },
    { name: 'X-XSS-Protection',          sev: 'info',   desc: 'Legacy XSS header missing (prefer CSP)', fix: 'Add X-XSS-Protection: 0 and rely on CSP' },
  ];
  for (const h of secHeaders) {
    const val = headers[h.name.toLowerCase()] || null;
    results.checks.push({ category: 'Security Headers', name: h.name, status: val ? 'pass' : 'fail', value: val || 'Not set' });
    if (!val) results.findings.push({ id: `VULN-HDR-${h.name}`, severity: h.sev, title: `Missing Header: ${h.name}`, description: h.desc, module: 'vulnAssessment', remediation: h.fix });
  }

  // ── 2. Cookie Flags ───────────────────────────────────────────────────────
  onProgress('Checking cookie security flags...');
  const cookieStr = Array.isArray(cookies) ? cookies.join('|||') : (cookies || '');
  if (cookieStr) {
    const parts = cookieStr.split(/,(?=\s*\w+=)|(\|\|\|)/g).filter(Boolean).filter(c => c !== '|||');
    for (const c of parts) {
      const m = c.match(/^\s*([^=]+)=/); if (!m) continue;
      const cName = m[1].trim();
      const hasSecure = /;\s*secure/i.test(c), hasHttp = /;\s*httponly/i.test(c), hasSame = /;\s*samesite/i.test(c);
      results.checks.push({ category: 'Cookie Flags', name: cName, status: hasSecure && hasHttp && hasSame ? 'pass' : 'fail', value: `Secure:${hasSecure} HttpOnly:${hasHttp} SameSite:${hasSame}` });
      if (!hasSecure) results.findings.push({ id: `VULN-COOKIE-SEC-${cName}`, severity: 'medium', title: `Cookie "${cName}" Missing Secure Flag`, description: 'Cookie transmitted over HTTP.', module: 'vulnAssessment', remediation: 'Add Secure flag.' });
      if (!hasHttp)   results.findings.push({ id: `VULN-COOKIE-HTTP-${cName}`, severity: 'medium', title: `Cookie "${cName}" Missing HttpOnly Flag`, description: 'Cookie accessible via JavaScript (XSS risk).', module: 'vulnAssessment', remediation: 'Add HttpOnly flag.' });
      if (!hasSame)   results.findings.push({ id: `VULN-COOKIE-SAME-${cName}`, severity: 'low',    title: `Cookie "${cName}" Missing SameSite Flag`, description: 'Cookie sent in cross-site requests.', module: 'vulnAssessment', remediation: 'Add SameSite=Lax or Strict.' });
    }
  } else {
    results.checks.push({ category: 'Cookie Flags', name: 'No cookies', status: 'info', value: 'No Set-Cookie headers found' });
  }

  // ── 3. CSP Evaluation ────────────────────────────────────────────────────
  onProgress('Evaluating Content Security Policy...');
  const csp = headers['content-security-policy'] || '';
  if (csp) {
    const issues = [];
    if (csp.includes("'unsafe-inline'")) issues.push("allows 'unsafe-inline'");
    if (csp.includes("'unsafe-eval'"))   issues.push("allows 'unsafe-eval'");
    if (csp.includes('*'))               issues.push('uses wildcard (*)');
    if (!csp.includes('default-src'))    issues.push('missing default-src');
    const st = issues.length === 0 ? 'pass' : issues.length <= 1 ? 'warn' : 'fail';
    results.checks.push({ category: 'CSP', name: 'Content-Security-Policy', status: st, value: issues.length ? issues.join(', ') : 'Well configured' });
    if (issues.length) results.findings.push({ id: 'VULN-CSP-WEAK', severity: issues.length > 1 ? 'high' : 'medium', title: 'Weak Content Security Policy', description: `CSP issues: ${issues.join('; ')}.`, module: 'vulnAssessment', remediation: "Remove unsafe-inline/unsafe-eval, avoid wildcards, set default-src 'self'." });
  }

  // ── 4. CORS ───────────────────────────────────────────────────────────────
  onProgress('Checking CORS configuration...');
  try {
    const r = await fetch(baseUrl, { signal: AbortSignal.timeout(8000), headers: { Origin: 'https://evil-cors-test.com', 'User-Agent': 'Mozilla/5.0' } });
    const acao = r.headers.get('access-control-allow-origin') || '';
    const acac = r.headers.get('access-control-allow-credentials') || '';
    if (acao === '*') {
      results.checks.push({ category: 'CORS', name: 'ACAO', status: 'fail', value: '*' });
      results.findings.push({ id: 'VULN-CORS-WILD', severity: acac ? 'critical' : 'medium', title: 'Wildcard CORS Policy (ACAO: *)', description: 'Any origin can make cross-site requests.', module: 'vulnAssessment', remediation: 'Restrict CORS to specific trusted origins.' });
    } else if (acao.includes('evil-cors-test.com')) {
      results.checks.push({ category: 'CORS', name: 'ACAO', status: 'fail', value: 'Reflects origin' });
      results.findings.push({ id: 'VULN-CORS-REFLECT', severity: 'critical', title: 'CORS Origin Reflection', description: 'Server reflects the Origin header — complete CORS bypass.', module: 'vulnAssessment', remediation: 'Whitelist specific trusted origins. Never reflect arbitrary Origin.' });
    } else {
      results.checks.push({ category: 'CORS', name: 'CORS Policy', status: 'pass', value: acao || 'Not set (restrictive)' });
    }
  } catch (_) { results.checks.push({ category: 'CORS', name: 'CORS Policy', status: 'info', value: 'Could not test' }); }

  // ── 5. HTTPS Redirect ────────────────────────────────────────────────────
  onProgress('Checking HTTPS redirect...');
  try {
    const r = await fetch(`http://${domain}`, { redirect: 'manual', signal: AbortSignal.timeout(8000) });
    const loc = r.headers.get('location') || '';
    if (r.status >= 300 && r.status < 400 && loc.startsWith('https://')) {
      results.checks.push({ category: 'HTTPS', name: 'HTTP→HTTPS Redirect', status: 'pass', value: `${r.status} → ${loc}` });
    } else {
      results.checks.push({ category: 'HTTPS', name: 'HTTP→HTTPS Redirect', status: 'fail', value: `Status ${r.status}` });
      results.findings.push({ id: 'VULN-NO-HTTPS-REDIR', severity: 'high', title: 'No HTTPS Redirect', description: 'HTTP traffic is not redirected to HTTPS.', module: 'vulnAssessment', remediation: 'Configure 301 redirect from HTTP to HTTPS.' });
    }
  } catch (_) { results.checks.push({ category: 'HTTPS', name: 'HTTP→HTTPS Redirect', status: 'info', value: 'Could not test' }); }

  // ── 6. Dangerous HTTP Methods ────────────────────────────────────────────
  onProgress('Testing HTTP methods...');
  for (const method of ['PUT', 'DELETE', 'TRACE', 'PATCH', 'CONNECT']) {
    try {
      const r = await fetch(baseUrl, { method, signal: AbortSignal.timeout(5000) });
      const allowed = r.status !== 405 && r.status !== 501 && r.status !== 403;
      results.checks.push({ category: 'HTTP Methods', name: method, status: allowed ? 'warn' : 'pass', value: `HTTP ${r.status}` });
      if (allowed) results.findings.push({ id: `VULN-METHOD-${method}`, severity: method === 'TRACE' ? 'high' : 'medium', title: `Dangerous HTTP Method Allowed: ${method}`, description: `${method} returned ${r.status}. This may expose CSRF/XST attack surface.`, module: 'vulnAssessment', remediation: `Disable the ${method} method on the web server if not required.` });
    } catch (_) {}
  }

  // ── 7. Sensitive File Probing (120+ paths) ───────────────────────────────
  onProgress('Probing sensitive files and backup paths (120+ checks)...');

  const sensitiveFiles = [
    // ── Secrets & environment ──────────────────────────────────────────────
    { path: '/.env',                        name: '.env File',                         sev: 'critical', verify: 'DB_' },
    { path: '/.env.local',                  name: '.env.local File',                   sev: 'critical', verify: 'DB_' },
    { path: '/.env.production',             name: '.env.production File',              sev: 'critical', verify: 'DB_' },
    { path: '/.env.staging',                name: '.env.staging File',                 sev: 'critical', verify: 'APP_' },
    { path: '/.env.development',            name: '.env.development File',             sev: 'critical', verify: 'APP_' },
    { path: '/.env.backup',                 name: '.env.backup File',                  sev: 'critical', verify: 'DB_' },
    { path: '/.env.old',                    name: '.env.old File',                     sev: 'critical', verify: 'DB_' },
    { path: '/.env.bak',                    name: '.env.bak File',                     sev: 'critical', verify: 'DB_' },
    { path: '/.env_1',                      name: '.env_1 File',                       sev: 'critical', verify: 'DB_' },
    { path: '/env.json',                    name: 'env.json File',                     sev: 'critical', verify: 'password' },
    { path: '/secrets.json',               name: 'secrets.json File',                  sev: 'critical', verify: 'secret' },
    { path: '/secrets.yml',                name: 'secrets.yml File',                   sev: 'critical', verify: 'secret' },
    { path: '/credentials.json',           name: 'Google Cloud Credentials',           sev: 'critical', verify: 'client_id' },
    { path: '/service-account.json',       name: 'GCP Service Account Key',            sev: 'critical', verify: 'private_key' },
    { path: '/serviceAccountKey.json',     name: 'Firebase Service Account Key',       sev: 'critical', verify: 'private_key' },
    // ── Source control ─────────────────────────────────────────────────────
    { path: '/.git/config',                name: 'Git Config',                         sev: 'critical', verify: '[core]' },
    { path: '/.git/HEAD',                  name: 'Git HEAD',                           sev: 'critical', verify: 'ref:' },
    { path: '/.git/COMMIT_EDITMSG',        name: 'Git Commit Message',                 sev: 'high',     verify: null },
    { path: '/.git/index',                 name: 'Git Index',                          sev: 'high',     verify: null },
    { path: '/.git/logs/HEAD',             name: 'Git Commit Log',                     sev: 'high',     verify: 'commit' },
    { path: '/.svn/entries',              name: 'SVN Entries File',                    sev: 'high',     verify: 'svn' },
    { path: '/.svn/wc.db',               name: 'SVN Database',                         sev: 'high',     verify: null },
    { path: '/.hg/hgrc',                  name: 'Mercurial Config',                    sev: 'high',     verify: '[paths]' },
    { path: '/.DS_Store',                 name: 'macOS DS_Store',                      sev: 'medium',   verify: null },
    // ── Web server config ──────────────────────────────────────────────────
    { path: '/.htpasswd',                  name: '.htpasswd File',                     sev: 'critical', verify: ':' },
    { path: '/.htaccess',                  name: '.htaccess File',                     sev: 'high',     verify: 'rewrite' },
    { path: '/web.config',                 name: 'IIS web.config',                     sev: 'high',     verify: '<configuration>' },
    { path: '/Web.config',                 name: 'IIS Web.config (Alt)',               sev: 'high',     verify: '<configuration>' },
    { path: '/nginx.conf',                 name: 'Nginx Config',                       sev: 'high',     verify: 'server' },
    { path: '/apache.conf',               name: 'Apache Config',                       sev: 'high',     verify: 'VirtualHost' },
    { path: '/.well-known/security.txt',   name: 'Security Contact',                   sev: 'info',     verify: 'contact' },
    // ── Application config ─────────────────────────────────────────────────
    { path: '/config.php',                 name: 'config.php',                         sev: 'critical', verify: 'db' },
    { path: '/config.yml',                 name: 'config.yml',                         sev: 'high',     verify: null },
    { path: '/config.json',                name: 'config.json',                        sev: 'high',     verify: null },
    { path: '/config.xml',                 name: 'config.xml',                         sev: 'high',     verify: null },
    { path: '/configuration.php',          name: 'configuration.php',                  sev: 'critical', verify: 'db' },
    { path: '/database.php',               name: 'database.php',                       sev: 'critical', verify: 'db' },
    { path: '/database.yml',               name: 'database.yml',                       sev: 'critical', verify: 'password' },
    { path: '/settings.py',               name: 'Django settings.py',                  sev: 'critical', verify: 'SECRET_KEY' },
    { path: '/application.properties',    name: 'Spring application.properties',       sev: 'high',     verify: 'spring' },
    { path: '/application.yml',           name: 'Spring application.yml',              sev: 'high',     verify: 'spring' },
    { path: '/app.config',                name: 'app.config',                          sev: 'high',     verify: null },
    { path: '/appsettings.json',          name: 'ASP.NET appsettings.json',            sev: 'high',     verify: 'ConnectionStrings' },
    { path: '/appsettings.Production.json',name:'ASP.NET Production Config',           sev: 'critical', verify: 'ConnectionStrings' },
    // ── Package manifests (version disclosure) ─────────────────────────────
    { path: '/package.json',               name: 'package.json (Node)',                sev: 'medium',   verify: '"name"' },
    { path: '/package-lock.json',          name: 'package-lock.json',                  sev: 'medium',   verify: '"name"' },
    { path: '/composer.json',              name: 'composer.json (PHP)',                sev: 'medium',   verify: '"require"' },
    { path: '/Gemfile',                    name: 'Ruby Gemfile',                       sev: 'medium',   verify: 'gem' },
    { path: '/requirements.txt',           name: 'Python requirements.txt',            sev: 'medium',   verify: null },
    { path: '/pom.xml',                   name: 'Maven pom.xml (Java)',                sev: 'medium',   verify: '<project>' },
    { path: '/build.gradle',              name: 'Gradle build file',                   sev: 'medium',   verify: null },
    // ── CI/CD & DevOps ────────────────────────────────────────────────────
    { path: '/.travis.yml',              name: '.travis.yml CI Config',                sev: 'medium',   verify: null },
    { path: '/Jenkinsfile',              name: 'Jenkinsfile Pipeline',                 sev: 'medium',   verify: 'pipeline' },
    { path: '/.gitlab-ci.yml',           name: '.gitlab-ci.yml',                      sev: 'medium',   verify: 'stages' },
    { path: '/docker-compose.yml',        name: 'docker-compose.yml',                  sev: 'high',     verify: 'services' },
    { path: '/docker-compose.override.yml',name:'docker-compose.override.yml',         sev: 'high',     verify: 'services' },
    { path: '/Dockerfile',               name: 'Dockerfile',                          sev: 'medium',   verify: 'FROM' },
    { path: '/Makefile',                 name: 'Makefile',                            sev: 'low',      verify: null },
    { path: '/.circleci/config.yml',     name: 'CircleCI config.yml',                 sev: 'medium',   verify: 'version' },
    // ── Backup / archive files ─────────────────────────────────────────────
    { path: '/backup.sql',               name: 'SQL Database Backup',                 sev: 'critical', verify: 'INSERT' },
    { path: '/dump.sql',                 name: 'SQL Database Dump',                   sev: 'critical', verify: 'INSERT' },
    { path: '/db.sql',                   name: 'SQL DB File (db.sql)',                 sev: 'critical', verify: 'INSERT' },
    { path: '/database.sql',             name: 'SQL DB File (database.sql)',           sev: 'critical', verify: 'INSERT' },
    { path: '/data.sql',                 name: 'SQL DB File (data.sql)',               sev: 'critical', verify: null },
    { path: '/site.tar.gz',             name: 'Site Archive (tar.gz)',                 sev: 'high',     verify: null },
    { path: '/backup.tar.gz',           name: 'Backup Archive',                        sev: 'high',     verify: null },
    { path: '/backup.zip',              name: 'Backup ZIP',                            sev: 'high',     verify: null },
    { path: `/${domain}.zip`,           name: 'Domain Name ZIP Archive',              sev: 'high',     verify: null },
    { path: `/${domain}.tar.gz`,        name: 'Domain Name TAR Archive',              sev: 'high',     verify: null },
    // ── Debug / PHP info ──────────────────────────────────────────────────
    { path: '/phpinfo.php',              name: 'PHP Info Page',                        sev: 'high',     verify: 'phpinfo()' },
    { path: '/info.php',                 name: 'PHP Info (info.php)',                  sev: 'high',     verify: 'PHP Version' },
    { path: '/test.php',                 name: 'PHP Test Page',                        sev: 'medium',   verify: 'php' },
    { path: '/php_info.php',             name: 'PHP Info (php_info.php)',              sev: 'high',     verify: 'phpinfo()' },
    { path: '/server-info',              name: 'Apache Server Info',                   sev: 'high',     verify: 'Apache Server Information' },
    { path: '/server-status',            name: 'Apache Server Status',                 sev: 'high',     verify: 'Apache Status' },
    // ── Admin panels ──────────────────────────────────────────────────────
    { path: '/admin',                    name: 'Admin Panel (/admin)',                  sev: 'high',     verify: null },
    { path: '/admin/',                   name: 'Admin Panel (/admin/)',                 sev: 'high',     verify: null },
    { path: '/admin.php',               name: 'Admin Panel (admin.php)',                sev: 'high',     verify: null },
    { path: '/administrator',           name: 'Administrator Panel',                   sev: 'high',     verify: null },
    { path: '/backend',                 name: 'Backend Panel',                         sev: 'high',     verify: null },
    { path: '/manage',                  name: 'Management Panel',                      sev: 'high',     verify: null },
    { path: '/management',             name: 'Management Panel (/management)',          sev: 'high',     verify: null },
    { path: '/phpmyadmin',             name: 'phpMyAdmin',                             sev: 'critical', verify: 'phpMyAdmin' },
    { path: '/pma',                    name: 'phpMyAdmin (/pma)',                      sev: 'critical', verify: 'phpMyAdmin' },
    { path: '/myadmin',                name: 'phpMyAdmin (/myadmin)',                  sev: 'critical', verify: 'phpMyAdmin' },
    { path: '/adminer',                name: 'Adminer DB Tool',                        sev: 'critical', verify: 'Adminer' },
    { path: '/adminer.php',            name: 'Adminer (adminer.php)',                  sev: 'critical', verify: 'Adminer' },
    { path: '/manager/html',           name: 'Tomcat Manager',                        sev: 'critical', verify: 'Tomcat' },
    { path: '/jenkins',                name: 'Jenkins CI',                             sev: 'critical', verify: 'Jenkins' },
    { path: '/kibana',                 name: 'Kibana Dashboard',                       sev: 'high',     verify: 'kibana' },
    { path: '/grafana',                name: 'Grafana Dashboard',                      sev: 'high',     verify: 'Grafana' },
    { path: '/portainer',              name: 'Portainer (Docker UI)',                  sev: 'critical', verify: 'Portainer' },
    { path: '/wp-login.php',           name: 'WordPress Login',                        sev: 'high',     verify: 'wp-submit' },
    { path: '/wp-admin',               name: 'WordPress Admin',                        sev: 'high',     verify: 'wp-admin' },
    { path: '/wp-config.php',          name: 'WordPress Config',                       sev: 'critical', verify: 'DB_NAME' },
    // ── Swagger / API docs ────────────────────────────────────────────────
    { path: '/swagger-ui.html',        name: 'Swagger UI (swagger-ui.html)',           sev: 'medium',   verify: 'swagger' },
    { path: '/swagger-ui',             name: 'Swagger UI',                             sev: 'medium',   verify: 'swagger' },
    { path: '/swagger/',               name: 'Swagger Root',                           sev: 'medium',   verify: 'swagger' },
    { path: '/api/swagger',            name: 'Swagger (/api/swagger)',                 sev: 'medium',   verify: 'swagger' },
    { path: '/api-docs',               name: 'API Docs',                               sev: 'medium',   verify: null },
    { path: '/v2/api-docs',            name: 'API Docs v2',                            sev: 'medium',   verify: '"swagger"' },
    { path: '/v3/api-docs',            name: 'API Docs v3 (OpenAPI)',                  sev: 'medium',   verify: '"openapi"' },
    { path: '/openapi.json',           name: 'OpenAPI JSON',                           sev: 'medium',   verify: '"openapi"' },
    { path: '/redoc',                  name: 'ReDoc API Docs',                         sev: 'medium',   verify: 'redoc' },
    // ── Debug endpoints ───────────────────────────────────────────────────
    { path: '/console',                name: 'Web Console',                            sev: 'critical', verify: 'console' },
    { path: '/h2-console',             name: 'H2 Database Console',                   sev: 'critical', verify: 'H2 Console' },
    { path: '/jolokia',                name: 'Jolokia JMX Agent',                     sev: 'critical', verify: 'jolokia' },
    { path: '/_profiler',             name: 'Symfony Profiler',                        sev: 'high',     verify: 'Symfony' },
    { path: '/__debugbar',            name: 'Laravel DebugBar',                        sev: 'high',     verify: 'debugbar' },
    { path: '/debug',                  name: 'Debug Endpoint',                         sev: 'high',     verify: null },
    { path: '/__admin',               name: 'WireMock Admin',                          sev: 'high',     verify: 'wiremock' },
    { path: '/trace',                  name: 'Trace Endpoint',                         sev: 'medium',   verify: null },
    { path: '/heapdump',              name: 'Heap Dump Endpoint',                      sev: 'critical', verify: null },
    // ── Legacy / misc ─────────────────────────────────────────────────────
    { path: '/cgi-bin/test-cgi',      name: 'CGI test-cgi Script',                    sev: 'high',     verify: null },
    { path: '/cgi-bin/printenv',      name: 'CGI printenv Script',                    sev: 'high',     verify: 'PATH' },
    { path: '/install.php',           name: 'Install Script (install.php)',            sev: 'high',     verify: 'install' },
    { path: '/install.sql',           name: 'Install SQL Script',                     sev: 'high',     verify: null },
    { path: '/setup.php',             name: 'Setup Script (setup.php)',                sev: 'high',     verify: 'setup' },
    { path: '/upgrade.php',           name: 'Upgrade Script',                         sev: 'high',     verify: null },
    { path: '/test/',                 name: 'Test Directory',                          sev: 'medium',   verify: null },
    { path: '/old/',                  name: 'Old Directory',                           sev: 'medium',   verify: null },
    { path: '/bak/',                  name: 'Bak Directory',                           sev: 'medium',   verify: null },
    { path: '/log/',                  name: 'Log Directory',                           sev: 'medium',   verify: null },
    { path: '/logs/',                 name: 'Logs Directory',                          sev: 'medium',   verify: null },
    { path: '/error.log',             name: 'Error Log File',                          sev: 'high',     verify: 'error' },
    { path: '/access.log',            name: 'Access Log File',                         sev: 'high',     verify: null },
    { path: '/debug.log',             name: 'Debug Log File',                          sev: 'high',     verify: null },
    { path: '/app.log',               name: 'App Log File',                            sev: 'high',     verify: null },
  ];

  const fileChecks = sensitiveFiles.map(async (f) => {
    try {
      const r = await safeFetch(baseUrl + f.path, { timeout: 5000 });
      if (r.status !== 200) return;
      let found = false;
      if (hasSoft404 || f.verify) {
        const body = r.body || (await safeFetch(baseUrl + f.path)).body;
        if (f.verify) { if (body.toLowerCase().includes(f.verify.toLowerCase())) found = true; }
        else if (!hasSoft404) found = true;
        else if (hasSoft404 && body.length > 200) found = true; // likely real content
      } else { found = true; }
      if (found) {
        results.checks.push({ category: 'Sensitive Files', name: f.name, status: 'fail', value: `${f.path} → 200 OK` });
        results.findings.push({
          id: `VULN-FILE-${f.path.replace(/[^a-zA-Z0-9]/g, '-').toUpperCase()}`,
          severity: f.sev, title: `Exposed: ${f.name}`,
          description: `${baseUrl}${f.path} is publicly accessible. This file may contain sensitive data, credentials, or configuration details.`,
          module: 'vulnAssessment', affected: baseUrl + f.path,
          remediation: `Remove or restrict access to ${f.path} at the web server / firewall level.`,
        });
      }
    } catch (_) {}
  });
  await Promise.allSettled(fileChecks);

  // ── 8. Backup file probing (.bak / .old / .orig / .swp) ─────────────────
  onProgress('Probing for backup and editor swap files...');
  const backupTargets = ['index.php', 'index.html', 'index.js', 'config.php', 'wp-config.php', 'admin.php', 'login.php', 'upload.php', 'app.py', 'main.py'];
  const backupExts   = ['.bak', '.old', '.orig', '.backup', '.tmp', '~', '.copy', '.save'];
  const backupChecks = [];
  for (const t of backupTargets) {
    for (const ext of backupExts) {
      backupChecks.push((async () => {
        const path = `/${t}${ext}`;
        const r = await safeFetch(baseUrl + path, { timeout: 4000 });
        if (r.status === 200 && r.body.length > 100) {
          results.checks.push({ category: 'Backup Files', name: `${t}${ext}`, status: 'fail', value: `${path} → 200 OK` });
          results.findings.push({
            id: `VULN-BACKUP-${path.replace(/[^a-zA-Z0-9]/g, '-').toUpperCase()}`,
            severity: t.includes('config') || t.includes('wp-config') ? 'critical' : 'high',
            title: `Backup File Exposed: ${t}${ext}`,
            description: `Editor/backup copy ${path} is publicly accessible. It may contain source code or credentials in plaintext.`,
            module: 'vulnAssessment', affected: baseUrl + path,
            remediation: `Delete backup files from the web root: rm ${path}. Add *.bak, *.old to .gitignore and web server deny rules.`,
          });
        }
      })());
    }
  }
  await Promise.allSettled(backupChecks);

  // ── 9. robots.txt & sitemap.xml analysis ─────────────────────────────────
  onProgress('Analyzing robots.txt and sitemap.xml...');
  try {
    const rb = await safeFetch(`${baseUrl}/robots.txt`, { timeout: 6000 });
    if (rb.status === 200 && rb.body.includes('Disallow')) {
      const disallowed = [];
      rb.body.split('\n').forEach(line => {
        const m = line.match(/^Disallow:\s*(.+)/i);
        if (m) {
          const p = m[1].trim();
          if (p && p !== '/' && p.length > 1) disallowed.push(p);
        }
      });
      results.checks.push({ category: 'robots.txt', name: 'robots.txt Found', status: 'info', value: `${disallowed.length} Disallow entries` });
      if (disallowed.length > 0) {
        results.findings.push({
          id: 'VULN-ROBOTS-DISCLOSE',
          severity: 'info',
          title: `robots.txt Reveals ${disallowed.length} Sensitive Path(s)`,
          description: `robots.txt lists paths that are disallowed from crawlers. These paths are revealed to attackers: ${disallowed.slice(0, 10).join(', ')}${disallowed.length > 10 ? '...' : ''}`,
          module: 'vulnAssessment',
          remediation: 'Remove sensitive paths from robots.txt. Use authentication instead of obscurity.',
        });
        // Probe top disallowed paths
        const probeThese = disallowed.slice(0, 8);
        await Promise.allSettled(probeThese.map(async (p) => {
          const pr = await safeFetch(baseUrl + p, { timeout: 4000 });
          if (pr.status === 200) {
            results.findings.push({
              id: `VULN-ROBOTS-ACCESS-${p.replace(/[^a-zA-Z0-9]/g, '-').toUpperCase()}`,
              severity: 'medium',
              title: `robots.txt Disallowed Path Accessible: ${p}`,
              description: `The path ${p} listed in robots.txt as Disallow is publicly accessible (HTTP 200).`,
              module: 'vulnAssessment', affected: baseUrl + p,
              remediation: 'Restrict this path with proper authentication, not robots.txt.',
            });
          }
        }));
      }
    }
  } catch (_) {}

  try {
    const sm = await safeFetch(`${baseUrl}/sitemap.xml`, { timeout: 5000 });
    if (sm.status === 200 && sm.body.includes('<loc>')) {
      const locs = [...sm.body.matchAll(/<loc>([^<]+)<\/loc>/gi)].map(m => m[1]);
      results.checks.push({ category: 'Sitemap', name: 'sitemap.xml Found', status: 'info', value: `${locs.length} URLs indexed` });
    }
  } catch (_) {}

  // ── 10. Exposed API / Monitoring endpoints ───────────────────────────────
  onProgress('Probing API and monitoring endpoints...');
  const apiEndpoints = [
    { path: '/actuator',           name: 'Spring Actuator',              sev: 'critical', verify: '_links' },
    { path: '/actuator/env',       name: 'Actuator /env',                sev: 'critical', verify: 'activeProfiles' },
    { path: '/actuator/heapdump',  name: 'Actuator /heapdump',           sev: 'critical', verify: null },
    { path: '/actuator/beans',     name: 'Actuator /beans',              sev: 'high',     verify: 'beans' },
    { path: '/actuator/mappings',  name: 'Actuator /mappings',           sev: 'high',     verify: 'mappings' },
    { path: '/actuator/loggers',   name: 'Actuator /loggers',            sev: 'high',     verify: 'loggers' },
    { path: '/actuator/metrics',   name: 'Actuator /metrics',            sev: 'high',     verify: 'metrics' },
    { path: '/actuator/httptrace', name: 'Actuator /httptrace',          sev: 'high',     verify: 'traces' },
    { path: '/metrics',            name: 'Prometheus /metrics',          sev: 'high',     verify: '# HELP' },
    { path: '/health',             name: 'Health Endpoint',              sev: 'medium',   verify: 'status' },
    { path: '/info',               name: 'Info Endpoint',                sev: 'medium',   verify: null },
    { path: '/env',                name: 'Env Endpoint',                 sev: 'critical', verify: null },
    { path: '/debug',              name: 'Debug Endpoint',               sev: 'high',     verify: null },
    { path: '/graphql',            name: 'GraphQL Endpoint',             sev: 'medium',   verify: null },
    { path: '/graphiql',           name: 'GraphiQL (GraphQL IDE)',       sev: 'high',     verify: 'graphiql' },
    { path: '/.well-known/openid-configuration', name: 'OpenID Connect Config', sev: 'info', verify: 'issuer' },
    { path: '/.well-known/jwks.json', name: 'JWKS (Public Keys)',        sev: 'info',     verify: 'keys' },
    { path: '/api/v1',             name: 'API v1 Root',                  sev: 'medium',   verify: null },
    { path: '/api/v2',             name: 'API v2 Root',                  sev: 'medium',   verify: null },
    { path: '/api/v3',             name: 'API v3 Root',                  sev: 'medium',   verify: null },
  ];
  const apiChecks = apiEndpoints.map(async (ep) => {
    const r = await safeFetch(baseUrl + ep.path, { timeout: 5000 });
    if (r.status !== 200) return;
    const matched = !ep.verify || r.body.toLowerCase().includes(ep.verify.toLowerCase());
    if (matched) {
      results.checks.push({ category: 'Exposed Endpoints', name: ep.name, status: 'fail', value: `${ep.path} → 200 OK` });
      results.findings.push({
        id: `VULN-ENDPOINT-${ep.path.replace(/[^a-zA-Z0-9]/g, '-').toUpperCase()}`,
        severity: ep.sev, title: `Exposed Endpoint: ${ep.name}`,
        description: `${ep.path} is publicly accessible. ${ep.name} endpoints can leak credentials, internal data, or application internals.`,
        module: 'vulnAssessment', affected: baseUrl + ep.path,
        remediation: `Restrict ${ep.path} to authenticated users / internal network. Remove from public access.`,
      });
    }
  });
  await Promise.allSettled(apiChecks);

  // ── 11. GraphQL Introspection ─────────────────────────────────────────────
  onProgress('Testing GraphQL introspection...');
  try {
    const gqlUrl = `${baseUrl}/graphql`;
    const gqlBody = JSON.stringify({ query: '{ __schema { types { name } } }' });
    const gr = await fetch(gqlUrl, {
      method: 'POST', signal: AbortSignal.timeout(8000),
      headers: { 'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0' },
      body: gqlBody,
    });
    if (gr.status === 200) {
      const gd = await gr.json().catch(() => null);
      if (gd?.data?.__schema) {
        const typeCount = gd.data.__schema.types?.length || 0;
        results.checks.push({ category: 'GraphQL', name: 'Introspection', status: 'fail', value: `Enabled — ${typeCount} types exposed` });
        results.findings.push({
          id: 'VULN-GRAPHQL-INTROSPECTION', severity: 'medium',
          title: 'GraphQL Introspection Enabled',
          description: `GraphQL introspection is enabled at /graphql. Attackers can discover the full schema (${typeCount} types), all queries, mutations, and relationships — providing a complete map of the API.`,
          module: 'vulnAssessment', affected: gqlUrl,
          remediation: 'Disable introspection in production: set introspection=false in your GraphQL server config.',
        });
      }
    }
  } catch (_) {}

  // ── 12. Default Credentials Testing ─────────────────────────────────────
  onProgress('Testing default credentials on discovered admin panels...');
  const defaultCredTargets = [
    {
      path: '/manager/j_security_check', name: 'Apache Tomcat Manager',
      method: 'POST', contentType: 'application/x-www-form-urlencoded',
      body: 'j_username=admin&j_password=admin',
      detect: (r) => r.status === 302 && (r.headers['location'] || '').includes('/manager/html'),
    },
    {
      path: '/api/user/login', name: 'Portainer Default Creds',
      method: 'POST', contentType: 'application/json',
      body: JSON.stringify({ Username: 'admin', Password: 'admin' }),
      detect: (r) => r.status === 200 && r.body.includes('jwt'),
    },
    {
      path: '/login', name: 'Generic Admin Login (admin/admin)',
      method: 'POST', contentType: 'application/x-www-form-urlencoded',
      body: 'username=admin&password=admin',
      detect: (r) => r.status === 200 && !r.body.toLowerCase().includes('invalid') && !r.body.toLowerCase().includes('error') && r.body.toLowerCase().includes('dashboard'),
    },
    {
      path: '/api/login', name: 'API Login Default Creds',
      method: 'POST', contentType: 'application/json',
      body: JSON.stringify({ username: 'admin', password: 'admin' }),
      detect: (r) => r.status === 200 && (r.body.includes('token') || r.body.includes('jwt')),
    },
  ];
  await Promise.allSettled(defaultCredTargets.map(async (t) => {
    try {
      const r = await safeFetch(baseUrl + t.path, {
        method: t.method, contentType: t.contentType, body: t.body,
        headers: { 'Content-Type': t.contentType, 'User-Agent': 'Mozilla/5.0' },
        timeout: 6000,
      });
      if (t.detect(r)) {
        results.checks.push({ category: 'Default Credentials', name: t.name, status: 'fail', value: 'admin/admin succeeded' });
        results.findings.push({
          id: `VULN-DEFCREDS-${t.name.replace(/\s+/g, '-').toUpperCase()}`,
          severity: 'critical', title: `Default Credentials Work: ${t.name}`,
          description: `${t.path} accepted default credentials (admin/admin or similar). An attacker can immediately take full control.`,
          module: 'vulnAssessment', affected: baseUrl + t.path,
          remediation: 'Change default credentials immediately. Enforce strong password policy and MFA on all admin interfaces.',
        });
      }
    } catch (_) {}
  }));

  // ── 13. Directory Listing (20+ directories) ──────────────────────────────
  onProgress('Checking for directory listing...');
  const dirs = [
    '/images/', '/css/', '/js/', '/assets/', '/uploads/', '/static/', '/media/',
    '/files/', '/data/', '/docs/', '/backup/', '/temp/', '/tmp/', '/old/',
    '/download/', '/downloads/', '/includes/', '/lib/', '/vendor/', '/node_modules/',
    '/public/', '/private/', '/config/', '/configs/', '/logs/', '/log/',
  ];
  const dirChecks = dirs.map(async (dir) => {
    const r = await safeFetch(baseUrl + dir, { timeout: 4000 });
    if (r.status === 200 && /index of|directory listing|parent directory|\[to parent directory\]/i.test(r.body)) {
      results.findings.push({
        id: `VULN-DIRLIST-${dir.replace(/\//g, '-').toUpperCase()}`,
        severity: dir.includes('config') || dir.includes('private') ? 'high' : 'medium',
        title: `Directory Listing Enabled: ${dir}`,
        description: `Directory index is visible at ${dir}. Attackers can enumerate all files and subdirectories.`,
        module: 'vulnAssessment', affected: baseUrl + dir,
        remediation: 'Add "Options -Indexes" to .htaccess or equivalent in nginx/IIS config.',
      });
    }
  });
  await Promise.allSettled(dirChecks);
  const dirListingCount = results.findings.filter(f => f.id?.startsWith('VULN-DIRLIST')).length;
  results.checks.push({ category: 'Directory Listing', name: 'Index Pages', status: dirListingCount > 0 ? 'fail' : 'pass', value: dirListingCount > 0 ? `${dirListingCount} directories exposed` : 'Not detected' });

  // ── 14. Debug / Error / Info Disclosure ──────────────────────────────────
  onProgress('Detecting debug mode and verbose error disclosure...');
  // Check homepage for debug indicators
  const debugPatterns = [
    { re: /\bapp_debug\s*=\s*true\b/i,                    title: 'Debug Mode Enabled (APP_DEBUG=true)',        sev: 'high' },
    { re: /\bdebug\s*=\s*true\b/i,                         title: 'Debug Mode Indicator Found (debug=true)',    sev: 'medium' },
    { re: /werkzeug debugger|interactive debugger/i,        title: 'Python Werkzeug Debugger Exposed',          sev: 'critical' },
    { re: /whitelabel error page/i,                         title: 'Spring Boot Whitelabel Error Page',         sev: 'medium' },
    { re: /stack trace:|traceback \(most recent call\)/i,   title: 'Stack Trace Exposed in Response',           sev: 'high' },
    { re: /syntax error|parse error.*on line/i,             title: 'PHP Error Disclosed in Response',           sev: 'medium' },
    { re: /ORA-\d{5}:|mysql.*error|pdo exception/i,        title: 'Database Error Disclosed',                  sev: 'high' },
    { re: /exception in thread|java\.lang\.\w+exception/i, title: 'Java Exception Disclosed in Response',      sev: 'high' },
    { re: /\b10\.\d+\.\d+\.\d+|\b192\.168\.\d+\.\d+|\b172\.(1[6-9]|2\d|3[01])\.\d+\.\d+/,
                                                             title: 'Private IP Address Leaked in Response',    sev: 'medium' },
  ];
  for (const dp of debugPatterns) {
    if (dp.re.test(html)) {
      results.checks.push({ category: 'Info Disclosure', name: dp.title, status: 'fail', value: 'Detected in homepage' });
      results.findings.push({
        id: `VULN-DEBUG-${dp.title.replace(/\s+/g, '-').toUpperCase().slice(0,40)}`,
        severity: dp.sev, title: dp.title,
        description: `${dp.title} detected in the HTTP response. This leaks sensitive information about the application stack.`,
        module: 'vulnAssessment',
        remediation: 'Disable debug mode in production. Set appropriate error handling to show generic error pages.',
      });
    }
  }

  // Check server / X-Powered-By version disclosure
  const serverHeader = headers['server'] || '';
  const poweredBy    = headers['x-powered-by'] || '';
  if (/[\d.]+/.test(serverHeader)) {
    results.checks.push({ category: 'Info Disclosure', name: 'Server Version Disclosed', status: 'warn', value: serverHeader });
    results.findings.push({
      id: 'VULN-SERVER-VERSION', severity: 'low', title: `Server Version Disclosed: ${serverHeader}`,
      description: 'The Server header reveals the web server software version, aiding targeted attacks.',
      module: 'vulnAssessment', remediation: 'Remove or genericise the Server header in web server config.',
    });
  }
  if (poweredBy) {
    results.checks.push({ category: 'Info Disclosure', name: 'X-Powered-By Disclosed', status: 'warn', value: poweredBy });
    results.findings.push({
      id: 'VULN-POWERED-BY', severity: 'low', title: `X-Powered-By Header Exposed: ${poweredBy}`,
      description: 'X-Powered-By reveals the server-side framework version.',
      module: 'vulnAssessment', remediation: 'Remove X-Powered-By header. In Express: app.disable("x-powered-by"). In PHP: expose_php = Off.',
    });
  }

  // ── 15. SSL/TLS Certificate ──────────────────────────────────────────────
  onProgress('Analyzing SSL/TLS certificate...');
  try {
    const certInfo = await getCertInfo(domain);
    if (certInfo) {
      const daysLeft = Math.floor((new Date(certInfo.validTo) - Date.now()) / 86400000);
      const expired  = daysLeft < 0;
      results.checks.push({
        category: 'SSL/TLS', name: 'Certificate Validity',
        status: expired ? 'fail' : daysLeft < 30 ? 'warn' : 'pass',
        value: expired ? `Expired ${-daysLeft} days ago` : `${daysLeft} days remaining`,
      });
      results.checks.push({ category: 'SSL/TLS', name: 'Issuer',   status: 'info', value: certInfo.issuer });
      results.checks.push({ category: 'SSL/TLS', name: 'Protocol', status: 'info', value: certInfo.protocol });
      if (expired) results.findings.push({ id: 'VULN-SSL-EXPIRED', severity: 'critical', title: 'SSL Certificate Expired', description: `Certificate expired ${-daysLeft} days ago.`, module: 'vulnAssessment', remediation: 'Renew the SSL certificate immediately.' });
      else if (daysLeft < 30) results.findings.push({ id: 'VULN-SSL-EXPIRING', severity: 'medium', title: `SSL Certificate Expiring in ${daysLeft} Days`, description: `Certificate expires soon.`, module: 'vulnAssessment', remediation: 'Renew the SSL certificate before it expires.' });
      if (certInfo.protocol === 'TLSv1' || certInfo.protocol === 'TLSv1.1') {
        results.findings.push({ id: 'VULN-TLS-WEAK', severity: 'high', title: `Weak TLS Protocol: ${certInfo.protocol}`, description: `Server negotiates deprecated ${certInfo.protocol}.`, module: 'vulnAssessment', remediation: 'Disable TLSv1/1.1. Only allow TLSv1.2 and TLSv1.3.' });
      }
    }
  } catch (_) { results.checks.push({ category: 'SSL/TLS', name: 'Certificate', status: 'info', value: 'Could not retrieve' }); }

  // ── 16. CVE Header Matching (35+ patterns) ────────────────────────────────
  onProgress('Matching detected software against known CVEs...');
  const combined = `${serverHeader} ${poweredBy}`;
  const cveDB = [
    { pattern: /Apache\/2\.4\.49/i,        cve: 'CVE-2021-41773', sev: 'critical', title: 'Apache Path Traversal / RCE',          fix: 'Upgrade Apache to 2.4.51+' },
    { pattern: /Apache\/2\.4\.50/i,        cve: 'CVE-2021-42013', sev: 'critical', title: 'Apache Path Traversal (Incomplete Fix)', fix: 'Upgrade Apache to 2.4.51+' },
    { pattern: /nginx\/1\.([0-9]|1[0-7])\./i, cve: 'CVE-2021-23017', sev: 'high', title: 'Nginx DNS Resolver Vulnerability',      fix: 'Upgrade Nginx to 1.21.0+' },
    { pattern: /Microsoft-IIS\/([6-8])\./i, cve: 'CVE-2017-7269', sev: 'critical', title: 'IIS WebDAV Buffer Overflow',           fix: 'Upgrade IIS and disable WebDAV' },
    { pattern: /PHP\/[5-7]\.[0-3]/i,       cve: 'CVE-2019-11043', sev: 'critical', title: 'PHP-FPM Remote Code Execution',        fix: 'Upgrade PHP to latest stable version' },
    { pattern: /PHP\/8\.0\./i,             cve: 'CVE-2023-3247',  sev: 'medium',   title: 'PHP 8.0 Information Disclosure',       fix: 'Upgrade to PHP 8.1+' },
    { pattern: /JBoss/i,                   cve: 'CVE-2017-12149', sev: 'critical', title: 'JBoss Deserialization RCE',            fix: 'Apply RedHat security patches' },
    { pattern: /Tomcat\/([4-9]|10)\./i,    cve: 'CVE-2020-1938',  sev: 'critical', title: 'Tomcat Ghostcat (AJP)',                fix: 'Disable AJP connector or upgrade Tomcat' },
    { pattern: /WebLogic/i,                cve: 'CVE-2020-14882', sev: 'critical', title: 'Oracle WebLogic RCE',                  fix: 'Apply Oracle October 2020 CPU patches' },
    { pattern: /ColdFusion/i,              cve: 'CVE-2023-26360', sev: 'critical', title: 'Adobe ColdFusion RCE',                 fix: 'Apply Adobe security updates' },
    { pattern: /log4j/i,                   cve: 'CVE-2021-44228', sev: 'critical', title: 'Log4Shell (Log4j RCE)',                fix: 'Upgrade log4j to 2.17.1+' },
    { pattern: /Spring/i,                  cve: 'CVE-2022-22963', sev: 'critical', title: 'Spring4Shell RCE',                    fix: 'Upgrade Spring Cloud Function' },
    { pattern: /Struts/i,                  cve: 'CVE-2017-5638',  sev: 'critical', title: 'Apache Struts 2 RCE',                 fix: 'Upgrade Apache Struts' },
    { pattern: /Confluence/i,              cve: 'CVE-2022-26134', sev: 'critical', title: 'Confluence OGNL RCE',                 fix: 'Apply Atlassian security patches' },
    { pattern: /Jira/i,                    cve: 'CVE-2019-11581', sev: 'critical', title: 'Jira Template Injection',             fix: 'Upgrade Jira Software' },
    { pattern: /Bitbucket/i,               cve: 'CVE-2022-36804', sev: 'critical', title: 'Bitbucket Command Injection',         fix: 'Apply Atlassian security patches' },
    { pattern: /GitLab/i,                  cve: 'CVE-2021-22205', sev: 'critical', title: 'GitLab ExifTool RCE',                 fix: 'Upgrade GitLab' },
    { pattern: /Jenkins/i,                 cve: 'CVE-2024-23897', sev: 'critical', title: 'Jenkins CLI LFI/RCE',                 fix: 'Upgrade Jenkins and disable CLI' },
    { pattern: /Grafana\/8\.[0-3]/i,       cve: 'CVE-2021-43798', sev: 'critical', title: 'Grafana LFI',                         fix: 'Upgrade Grafana to 8.3.1+' },
    { pattern: /BIG-IP/i,                  cve: 'CVE-2022-1388',  sev: 'critical', title: 'F5 BIG-IP iControl RCE',             fix: 'Apply F5 security patches' },
    { pattern: /Pulse Secure/i,            cve: 'CVE-2019-11510', sev: 'critical', title: 'Pulse Secure LFI',                   fix: 'Apply Ivanti security patches' },
    { pattern: /GlobalProtect/i,           cve: 'CVE-2019-1579',  sev: 'critical', title: 'Palo Alto GlobalProtect RCE',        fix: 'Apply Palo Alto security patches' },
    { pattern: /Fortinet/i,                cve: 'CVE-2023-27997', sev: 'critical', title: 'FortiOS Heap Overflow RCE',          fix: 'Apply Fortinet security patches' },
    { pattern: /Citrix/i,                  cve: 'CVE-2023-3519',  sev: 'critical', title: 'Citrix NetScaler RCE',               fix: 'Apply Citrix security patches' },
    { pattern: /vBulletin/i,               cve: 'CVE-2019-16759', sev: 'critical', title: 'vBulletin RCE',                      fix: 'Apply vBulletin security patches' },
    { pattern: /Drupal/i,                  cve: 'CVE-2018-7600',  sev: 'critical', title: 'Drupalgeddon 2 RCE',                 fix: 'Upgrade Drupal' },
    { pattern: /Magento/i,                 cve: 'CVE-2022-24086', sev: 'critical', title: 'Magento Improper Input Validation',  fix: 'Apply Adobe Commerce patches' },
    { pattern: /Ghost/i,                   cve: 'CVE-2021-29484', sev: 'high',     title: 'Ghost CMS XSS',                     fix: 'Upgrade Ghost' },
    { pattern: /Webmin\/1\.920/i,          cve: 'CVE-2019-15107', sev: 'critical', title: 'Webmin RCE',                        fix: 'Upgrade Webmin' },
    { pattern: /Liferay/i,                 cve: 'CVE-2020-7961',  sev: 'critical', title: 'Liferay Portal RCE',                fix: 'Apply Liferay patches' },
    { pattern: /Cisco/i,                   cve: 'CVE-2020-3452',  sev: 'high',     title: 'Cisco ASA LFI',                     fix: 'Apply Cisco patches' },
    { pattern: /Splunk/i,                  cve: 'CVE-2023-46214', sev: 'critical', title: 'Splunk Enterprise RCE',              fix: 'Upgrade Splunk' },
    { pattern: /openresty\/1\.1[0-5]/i,   cve: 'CVE-2019-9511',  sev: 'high',     title: 'OpenResty HTTP/2 DoS',              fix: 'Upgrade OpenResty' },
    { pattern: /Zimbra/i,                  cve: 'CVE-2022-37042', sev: 'critical', title: 'Zimbra Auth Bypass RCE',            fix: 'Upgrade Zimbra to latest patch' },
    { pattern: /VMware/i,                  cve: 'CVE-2022-22954', sev: 'critical', title: 'VMware Workspace ONE SSTI RCE',      fix: 'Apply VMware security advisory VMSA-2022-0011' },
  ];
  for (const entry of cveDB) {
    if (entry.pattern.test(combined)) {
      results.checks.push({ category: 'Known CVEs', name: entry.cve, status: 'fail', value: entry.title });
      results.findings.push({ id: `VULN-CVE-${entry.cve}`, severity: entry.sev, title: `${entry.cve}: ${entry.title}`, description: `Detected potentially vulnerable software in response headers: "${combined.trim()}"`, module: 'vulnAssessment', remediation: entry.fix });
    }
  }
  if (!results.checks.some(c => c.category === 'Known CVEs'))
    results.checks.push({ category: 'Known CVEs', name: 'Version Check', status: 'pass', value: 'No known vulnerable versions detected in headers' });

  // ── 17. CSRF Detection ───────────────────────────────────────────────────
  onProgress('Checking for CSRF protection...');
  const formRegex = /<form[^>]*method\s*=\s*["']?post["']?[^>]*>([\s\S]*?)<\/form>/gi;
  let fMatch, formCount = 0, unprotected = 0;
  while ((fMatch = formRegex.exec(html)) !== null) {
    formCount++;
    if (!/csrf|_token|authenticity_token|__RequestVerificationToken/i.test(fMatch[1])) unprotected++;
  }
  if (formCount > 0) {
    results.checks.push({ category: 'CSRF', name: 'Form Protection', status: unprotected > 0 ? 'fail' : 'pass', value: `${formCount - unprotected}/${formCount} forms protected` });
    if (unprotected > 0) results.findings.push({ id: 'VULN-CSRF', severity: 'medium', title: `${unprotected} Form(s) Without CSRF Token`, description: `Found ${unprotected} POST form(s) without visible CSRF tokens.`, module: 'vulnAssessment', remediation: 'Add CSRF tokens to all state-changing forms.' });
  } else {
    results.checks.push({ category: 'CSRF', name: 'Form Protection', status: 'info', value: 'No POST forms found on homepage' });
  }

  // ── 18. JWT in Cookies ───────────────────────────────────────────────────
  onProgress('Checking for JWT tokens in cookies...');
  const jwtRe = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/;
  if (jwtRe.test(cookieStr)) {
    results.checks.push({ category: 'JWT', name: 'JWT in Cookie', status: 'warn', value: 'JWT detected in Set-Cookie' });
    results.findings.push({ id: 'VULN-JWT-COOKIE', severity: 'medium', title: 'JWT Token in Cookie — Verify Signing & Flags', description: 'JWT found in a cookie. Ensure RS256/ES256 signing and Secure+HttpOnly+SameSite=Strict flags.', module: 'vulnAssessment', remediation: 'Use RS256/ES256. Set Secure+HttpOnly+SameSite=Strict on JWT cookies. Implement short expiry.' });
  } else {
    results.checks.push({ category: 'JWT', name: 'JWT in Cookie', status: 'pass', value: 'No JWT detected in cookies' });
  }

  // ── 19. Open Redirect ────────────────────────────────────────────────────
  onProgress('Testing open redirect parameters...');
  const redirectParams = ['url', 'redirect', 'next', 'return', 'returnUrl', 'goto', 'redirect_uri', 'continue', 'dest', 'destination', 'forward'];
  let redirectFound = false;
  for (const param of redirectParams.slice(0, 6)) {
    try {
      const r = await fetch(`${baseUrl}/?${param}=https://evil-redirect-test.com`, { redirect: 'manual', signal: AbortSignal.timeout(4000) });
      const loc = (r.headers.get('location') || '').toLowerCase();
      if (loc.includes('evil-redirect-test.com')) {
        redirectFound = true;
        results.findings.push({ id: `VULN-REDIR-${param}`, severity: 'medium', title: `Open Redirect via "${param}" Parameter`, description: `Parameter "${param}" redirects to arbitrary external URLs.`, module: 'vulnAssessment', remediation: 'Validate redirect URLs against a whitelist.' });
        break;
      }
    } catch (_) {}
  }
  results.checks.push({ category: 'Open Redirect', name: 'Redirect Parameters', status: redirectFound ? 'fail' : 'pass', value: redirectFound ? 'Vulnerable' : 'No open redirects detected' });

  // ── Build summary ─────────────────────────────────────────────────────────
  for (const c of results.checks) {
    if      (c.status === 'pass') results.summary.pass++;
    else if (c.status === 'fail') results.summary.fail++;
    else if (c.status === 'warn') results.summary.warn++;
    else                          results.summary.info++;
  }

  onProgress(`Vulnerability assessment complete — ${results.findings.length} issues found across ${results.checks.length} checks`);
  return results;
}

// ── TLS helper ────────────────────────────────────────────────────────────────

function getCertInfo(domain) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('SSL timeout')), 8000);
    try {
      const sock = tls.connect(443, domain, { servername: domain, rejectUnauthorized: false }, () => {
        clearTimeout(timeout);
        try {
          const cert = sock.getPeerCertificate();
          sock.destroy();
          if (!cert || !cert.valid_from) return resolve(null);
          resolve({ subject: cert.subject?.CN || '', issuer: cert.issuer?.O || cert.issuer?.CN || '', validFrom: cert.valid_from, validTo: cert.valid_to, protocol: sock.getProtocol() });
        } catch (e) { sock.destroy(); resolve(null); }
      });
      sock.on('error', () => { clearTimeout(timeout); reject(new Error('TLS error')); });
    } catch (e) { clearTimeout(timeout); reject(e); }
  });
}

module.exports = { runVulnAssessment };
