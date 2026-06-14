'use strict';
/**
 * cmsVulnScan.js — CMS & Framework-Specific Vulnerability Scanner
 * Detects WordPress, Drupal, Joomla, Laravel, Django, Spring Boot, and more.
 * Runs targeted checks against each detected platform.
 */

const FETCH_OPTS = {
  redirect: 'follow',
  headers: { 'User-Agent': 'Mozilla/5.0 (compatible; ReconScan/1.0)', Accept: 'text/html,*/*' },
};

async function safeFetch(url, extra = {}) {
  try {
    const r = await fetch(url, { ...FETCH_OPTS, ...extra, signal: AbortSignal.timeout(7000) });
    const text = await r.text();
    return { ok: true, status: r.status, text, headers: Object.fromEntries(r.headers.entries()) };
  } catch (_) { return { ok: false, status: 0, text: '', headers: {} }; }
}

// ── CMS Fingerprints ─────────────────────────────────────────────────────────

function detectCMS(html, headers) {
  const detected = [];
  const h = JSON.stringify(headers).toLowerCase();

  // WordPress
  if (/wp-content|wp-includes|wordpress/i.test(html) || /wordpress/i.test(h))
    detected.push({ name: 'WordPress', icon: '📰' });

  // Drupal
  if (/drupal\.js|drupal\.settings|X-Generator.*Drupal/i.test(html + h))
    detected.push({ name: 'Drupal', icon: '💧' });

  // Joomla
  if (/joomla|\/components\/com_/i.test(html))
    detected.push({ name: 'Joomla', icon: '🔥' });

  // Magento
  if (/mage\.|magento|\/skin\/frontend\//i.test(html))
    detected.push({ name: 'Magento', icon: '🛒' });

  // Shopify
  if (/shopify|cdn\.shopify\.com/i.test(html))
    detected.push({ name: 'Shopify', icon: '🛍️' });

  // Laravel
  if (/laravel_session|XSRF-TOKEN.*laravel|laravel/i.test(html + JSON.stringify(headers)))
    detected.push({ name: 'Laravel', icon: '🔴' });

  // Django
  if (/csrfmiddlewaretoken|django|__django/i.test(html))
    detected.push({ name: 'Django', icon: '🎸' });

  // Spring Boot
  if (/whitelabel error page|spring boot|x-application-context/i.test(html + h))
    detected.push({ name: 'Spring Boot', icon: '🌿' });

  // Express.js
  if (/x-powered-by.*express/i.test(h))
    detected.push({ name: 'Express.js', icon: '⚡' });

  // Next.js
  if (/__NEXT_DATA__|_next\/static/i.test(html))
    detected.push({ name: 'Next.js', icon: '▲' });

  return detected;
}

// ── Platform-Specific Checks ─────────────────────────────────────────────────

const PLATFORM_CHECKS = {

  WordPress: [
    { path: '/wp-json/wp/v2/users', name: 'User Enumeration via REST API', sev: 'high',
      detect: (r) => r.ok && r.status === 200 && r.text.includes('"id"') && r.text.includes('"slug"'),
      desc: 'WordPress REST API exposes user list. Attackers can enumerate all usernames.',
      fix: 'Add to functions.php: add_filter("rest_endpoints", function($e){ unset($e["/wp/v2/users"]); return $e; });' },
    { path: '/xmlrpc.php', name: 'XML-RPC Enabled', sev: 'medium',
      detect: (r) => r.ok && r.status === 200 && /xmlrpc/i.test(r.text),
      desc: 'XML-RPC is enabled and can be abused for brute-force attacks and DDoS amplification.',
      fix: 'Disable XML-RPC via plugin (Disable XML-RPC) or add to .htaccess: deny from all for /xmlrpc.php.' },
    { path: '/wp-content/debug.log', name: 'Debug Log Exposed', sev: 'high',
      detect: (r) => r.ok && r.status === 200 && r.text.length > 50,
      desc: 'WordPress debug log is publicly accessible. May contain sensitive data and stack traces.',
      fix: 'Move debug log out of web root or restrict access in .htaccess.' },
    { path: '/wp-config.php.bak', name: 'WordPress Config Backup', sev: 'critical',
      detect: (r) => r.ok && r.status === 200,
      desc: 'WordPress configuration backup is publicly accessible. May expose DB credentials.',
      fix: 'Delete backup files from the web root immediately.' },
    { path: '/.wp-config.php.swp', name: 'WordPress Config Swap File', sev: 'critical',
      detect: (r) => r.ok && r.status === 200,
      desc: 'Editor swap file for wp-config.php is publicly accessible.',
      fix: 'Delete .swp and similar editor temp files from the server.' },
    { path: '/wp-login.php', name: 'Login Page Accessible', sev: 'low',
      detect: (r) => r.ok && r.status === 200 && /log in|wordpress/i.test(r.text),
      desc: 'WordPress login page is publicly accessible. Subject to brute-force attacks.',
      fix: 'Add IP-based restrictions, use 2FA, or move login URL with a plugin.' },
    { path: '/readme.html', name: 'WordPress Version Disclosed', sev: 'medium',
      detect: (r) => r.ok && r.status === 200 && /wordpress/i.test(r.text),
      desc: 'README.html discloses the WordPress version, aiding targeted attacks.',
      fix: 'Delete readme.html from the WordPress root directory.' },
  ],

  Drupal: [
    { path: '/CHANGELOG.txt', name: 'Drupal Version Disclosed (CHANGELOG)', sev: 'medium',
      detect: (r) => r.ok && r.status === 200 && /drupal/i.test(r.text),
      desc: 'CHANGELOG.txt reveals the exact Drupal version, enabling targeted exploits.',
      fix: 'Delete or block access to CHANGELOG.txt in .htaccess.' },
    { path: '/INSTALL.txt', name: 'Drupal Install File Exposed', sev: 'low',
      detect: (r) => r.ok && r.status === 200 && /drupal/i.test(r.text),
      desc: 'INSTALL.txt exposes Drupal version and configuration guidance.',
      fix: 'Delete or restrict access to INSTALL.txt.' },
    { path: '/?q=user/register', name: 'Drupal Open User Registration', sev: 'medium',
      detect: (r) => r.ok && r.status === 200 && /create.*account|register/i.test(r.text),
      desc: 'Drupal user registration is open to the public.',
      fix: 'In Drupal admin: Configuration → Account settings → set "Who can register accounts" to Administrators only.' },
    { path: '/sites/default/files/', name: 'Drupal Files Directory Listing', sev: 'medium',
      detect: (r) => r.ok && r.status === 200 && /index of/i.test(r.text),
      desc: 'Directory listing is enabled on the files directory.',
      fix: 'Add Options -Indexes to .htaccess in sites/default/files/.' },
  ],

  Joomla: [
    { path: '/administrator', name: 'Joomla Admin Panel Exposed', sev: 'high',
      detect: (r) => r.ok && r.status === 200 && /joomla|administrator/i.test(r.text),
      desc: 'Joomla administrator panel is publicly accessible.',
      fix: 'Restrict /administrator to trusted IP addresses.' },
    { path: '/configuration.php.bak', name: 'Joomla Config Backup', sev: 'critical',
      detect: (r) => r.ok && r.status === 200,
      desc: 'Joomla configuration backup file is publicly accessible. May expose DB credentials.',
      fix: 'Delete all backup config files from the web root.' },
    { path: '/README.txt', name: 'Joomla Version Disclosure', sev: 'medium',
      detect: (r) => r.ok && r.status === 200 && /joomla/i.test(r.text),
      desc: 'README.txt exposes Joomla version.',
      fix: 'Delete README.txt from the Joomla root.' },
  ],

  Laravel: [
    { path: '/_ignition/execute-solution', name: 'Laravel Ignition RCE (CVE-2021-3129)', sev: 'critical',
      detect: (r) => r.ok && r.status === 200 && /ignition|flare|laravel.*error|whoops/i.test(r.text),
      desc: 'Ignition debug page is accessible. CVE-2021-3129 allows Remote Code Execution on Laravel ≤8.4.2.',
      fix: 'Update Laravel to ≥8.4.3. Set APP_DEBUG=false in production.' },
    { path: '/telescope', name: 'Laravel Telescope Debug Tool Exposed', sev: 'high',
      detect: (r) => r.ok && r.status === 200 && /telescope/i.test(r.text),
      desc: 'Laravel Telescope is publicly accessible. It exposes all requests, queries, and logs.',
      fix: 'Restrict Telescope to authenticated admin users only. Set TELESCOPE_ENABLED=false in production.' },
    { path: '/horizon', name: 'Laravel Horizon Exposed', sev: 'high',
      detect: (r) => r.ok && r.status === 200 && /horizon|queue/i.test(r.text),
      desc: 'Laravel Horizon queue dashboard is publicly accessible.',
      fix: 'Add authentication gate to Horizon. Restrict access by IP.' },
    { path: '/.env', name: 'Laravel .env File Exposed', sev: 'critical',
      detect: (r) => r.ok && r.status === 200 && /APP_KEY|DB_PASSWORD/i.test(r.text),
      desc: '.env file containing application secrets is publicly accessible.',
      fix: 'Remove .env from web root. Ensure web server is not serving dotfiles.' },
  ],

  Django: [
    { path: '/admin/', name: 'Django Admin Panel Accessible', sev: 'medium',
      detect: (r) => r.ok && r.status === 200 && /django.*administration|log in.*django/i.test(r.text),
      desc: 'Django admin panel is publicly accessible.',
      fix: 'Move Django admin to a non-standard URL. Restrict by IP.' },
    { path: '/static/admin/css/base.css', name: 'Django Admin Assets Exposed', sev: 'info',
      detect: (r) => r.ok && r.status === 200,
      desc: 'Django admin static assets are accessible, confirming Django is in use.',
      fix: 'No immediate action required, but consider security hardening.' },
  ],

  'Spring Boot': [
    { path: '/actuator', name: 'Spring Boot Actuator Exposed', sev: 'critical',
      detect: (r) => r.ok && r.status === 200 && /actuator|_links/i.test(r.text),
      desc: 'Spring Boot Actuator endpoint is publicly accessible. Exposes app internals, environment variables, and heap dumps.',
      fix: 'Restrict actuator endpoints to management port only. Add security: management.endpoints.web.exposure.include=health,info' },
    { path: '/actuator/env', name: 'Spring Boot Actuator /env Exposed', sev: 'critical',
      detect: (r) => r.ok && r.status === 200 && /systemProperties|activeProfiles/i.test(r.text),
      desc: 'Actuator /env exposes all environment variables including secrets and credentials.',
      fix: 'Exclude env from actuator endpoints: management.endpoints.web.exposure.exclude=env,beans,heapdump' },
    { path: '/actuator/heapdump', name: 'Spring Boot Heap Dump Accessible', sev: 'critical',
      detect: (r) => r.ok && r.status === 200 && r.headers['content-type']?.includes('octet-stream'),
      desc: 'Spring Boot heap dump is accessible. Contains full application memory including credentials and secrets.',
      fix: 'Immediately exclude heapdump from actuator: management.endpoints.web.exposure.exclude=heapdump' },
    { path: '/actuator/loggers', name: 'Spring Boot Loggers Endpoint', sev: 'high',
      detect: (r) => r.ok && r.status === 200 && /loggers/i.test(r.text),
      desc: 'Actuator /loggers allows changing log levels at runtime (potential information disclosure).',
      fix: 'Restrict loggers actuator endpoint access.' },
  ],

  'Express.js': [
    { path: '/api/v1', name: 'Express API v1 Endpoint', sev: 'info',
      // Require JSON response body to confirm it is a real API, not a catch-all SPA route
      detect: (r) => r.ok && r.status === 200 && (r.headers['content-type'] || '').includes('json'),
      desc: 'API v1 JSON endpoint exists. Check for missing authentication and rate limiting.',
      fix: 'Ensure all API endpoints require authentication and implement rate limiting.' },
  ],

  'Next.js': [
    { path: '/_next/static/', name: 'Next.js Static Assets Exposed', sev: 'info',
      // Only flag if directory listing is enabled (index of), otherwise it's normal
      detect: (r) => r.status === 200 && /index of|\[dir\]/i.test(r.text),
      desc: 'Next.js static assets directory listing is enabled. Build IDs and chunk hashes are disclosed.',
      fix: 'Disable directory listing on the web server. Ensure source maps are not exposed in production.' },
    { path: '/api/auth', name: 'Next.js Auth API Exposed', sev: 'info',
      detect: (r) => r.status !== 404,
      desc: 'Next.js auth API is present. Ensure NEXTAUTH_SECRET is set and all callbacks are secure.',
      fix: 'Set NEXTAUTH_SECRET. Ensure callback URLs are validated.' },
  ],
};

// ── Main Module ───────────────────────────────────────────────────────────────

async function runCMSVulnScan(domain, onProgress) {
  const results = {
    domain,
    detectedPlatforms: [],
    checks: [],
    findings: [],
    summary: { platforms: 0, checksRun: 0, passed: 0, failed: 0 },
  };

  const baseUrls = [`https://${domain}`, `http://${domain}`];
  let baseUrl = '', homeHtml = '', homeHeaders = {};

  onProgress('Fetching target for CMS/framework detection...');
  for (const url of baseUrls) {
    const r = await safeFetch(url);
    if (r.ok) { baseUrl = url; homeHtml = r.text; homeHeaders = r.headers; break; }
  }

  if (!baseUrl) { onProgress('Target unreachable — skipping CMS scan'); return results; }

  // ── Detect CMS ──────────────────────────────────────────────────────────────
  onProgress('Identifying CMS and frameworks...');
  const detected = detectCMS(homeHtml, homeHeaders);
  results.detectedPlatforms = detected;
  results.summary.platforms = detected.length;

  if (detected.length === 0) {
    onProgress('No known CMS/framework detected — running generic checks');
    results.checks.push({ name: 'CMS Detection', status: 'info', detail: 'No known CMS/framework detected from page signals' });
    return results;
  }

  // ── Run Platform-Specific Checks ────────────────────────────────────────────
  for (const platform of detected) {
    const checks = PLATFORM_CHECKS[platform.name] || [];
    onProgress(`Running ${platform.name} vulnerability checks (${checks.length} checks)...`);

    for (const check of checks) {
      results.summary.checksRun++;
      const r = await safeFetch(baseUrl + check.path);
      const vulnerable = check.detect(r);

      results.checks.push({
        platform: platform.name,
        name: check.name,
        path: check.path,
        status: vulnerable ? 'fail' : 'pass',
        httpStatus: r.status,
      });

      if (vulnerable) {
        results.summary.failed++;
        results.findings.push({
          id: `CMS-${platform.name.toUpperCase().replace(/\s/g,'-')}-${check.name.replace(/\s+/g,'-').toUpperCase()}`,
          severity: check.sev,
          title: `[${platform.name}] ${check.name}`,
          description: check.desc,
          module: 'cmsVulnScan',
          affected: baseUrl + check.path,
          remediation: check.fix,
          platform: platform.name,
          owasp: check.owasp || 'A05:2021 Security Misconfiguration',
        });
      } else {
        results.summary.passed++;
      }
    }
  }

  onProgress(`CMS scan complete — ${results.findings.length} issue(s) across ${detected.map(d=>d.name).join(', ')}`);
  return results;
}

module.exports = { runCMSVulnScan };
