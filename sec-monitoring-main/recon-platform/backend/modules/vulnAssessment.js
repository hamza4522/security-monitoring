const tls = require('tls');
const https = require('https');

async function runVulnAssessment(domain, onProgress) {
  const results = { domain, checks: [], findings: [], summary: { pass: 0, fail: 0, warn: 0, info: 0 } };
  const baseUrls = [`https://${domain}`, `http://${domain}`];
  let html = '', headers = {}, baseUrl = '', cookies = '';

  onProgress('Fetching target for vulnerability assessment...');
  for (const url of baseUrls) {
    try {
      const r = await fetch(url, { redirect: 'follow', signal: AbortSignal.timeout(12000),
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0' } });
      html = await r.text(); headers = Object.fromEntries(r.headers.entries());
      cookies = headers['set-cookie'] || ''; baseUrl = url; break;
    } catch (_) {}
  }
  if (!baseUrl) { onProgress('Target unreachable'); return results; }

  // 1. Security Headers
  onProgress('Checking HTTP security headers...');
  const secHeaders = [
    { name: 'Strict-Transport-Security', sev: 'high', desc: 'HSTS not set — browsers can be tricked into HTTP connections',
      fix: 'Add header: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload' },
    { name: 'X-Frame-Options', sev: 'medium', desc: 'Clickjacking protection missing',
      fix: 'Add header: X-Frame-Options: DENY or SAMEORIGIN' },
    { name: 'X-Content-Type-Options', sev: 'medium', desc: 'MIME-sniffing protection missing',
      fix: 'Add header: X-Content-Type-Options: nosniff' },
    { name: 'Referrer-Policy', sev: 'low', desc: 'Referrer policy not configured',
      fix: 'Add header: Referrer-Policy: strict-origin-when-cross-origin' },
    { name: 'Permissions-Policy', sev: 'low', desc: 'Permissions policy not set',
      fix: 'Add Permissions-Policy header to restrict browser features' },
    { name: 'X-XSS-Protection', sev: 'info', desc: 'Legacy XSS protection header missing (modern CSP preferred)',
      fix: 'Add X-XSS-Protection: 0 (rely on CSP instead)' },
  ];
  for (const h of secHeaders) {
    const present = !!headers[h.name.toLowerCase()];
    const val = headers[h.name.toLowerCase()] || null;
    results.checks.push({ category: 'Security Headers', name: h.name, status: present ? 'pass' : 'fail', value: val });
    if (!present) {
      results.findings.push({ id: `VULN-HDR-${h.name}`, severity: h.sev, title: `Missing ${h.name} Header`,
        description: h.desc, module: 'vulnAssessment', remediation: h.fix });
    }
  }

  // 2. Cookie Flags
  onProgress('Checking cookie security flags...');
  const cookieStr = Array.isArray(cookies) ? cookies.join('|||') : cookies;
  if (cookieStr) {
    const parts = cookieStr.split(/,(?=\s*\w+=)|(\|\|\|)/g).filter(Boolean).filter(c => c !== '|||');
    for (const c of parts) {
      const nameMatch = c.match(/^\s*([^=]+)=/);
      if (!nameMatch) continue;
      const cName = nameMatch[1].trim();
      const hasSecure = /;\s*secure/i.test(c), hasHttp = /;\s*httponly/i.test(c), hasSame = /;\s*samesite/i.test(c);
      results.checks.push({ category: 'Cookie Flags', name: cName,
        status: hasSecure && hasHttp && hasSame ? 'pass' : 'fail',
        value: `Secure:${hasSecure} HttpOnly:${hasHttp} SameSite:${hasSame}` });
      if (!hasSecure) results.findings.push({ id: `VULN-COOKIE-SEC-${cName}`, severity: 'medium',
        title: `Cookie "${cName}" missing Secure flag`, description: 'Cookie can be sent over unencrypted HTTP.',
        module: 'vulnAssessment', remediation: 'Add the Secure flag to this cookie.' });
      if (!hasHttp) results.findings.push({ id: `VULN-COOKIE-HTTP-${cName}`, severity: 'medium',
        title: `Cookie "${cName}" missing HttpOnly flag`, description: 'Cookie accessible via JavaScript (XSS risk).',
        module: 'vulnAssessment', remediation: 'Add the HttpOnly flag to this cookie.' });
      if (!hasSame) results.findings.push({ id: `VULN-COOKIE-SAME-${cName}`, severity: 'low',
        title: `Cookie "${cName}" missing SameSite flag`, description: 'Cookie may be sent in cross-site requests.',
        module: 'vulnAssessment', remediation: 'Add SameSite=Lax or SameSite=Strict.' });
    }
  } else {
    results.checks.push({ category: 'Cookie Flags', name: 'No cookies', status: 'info', value: 'No Set-Cookie headers found' });
  }

  // 3. CSP Evaluation
  onProgress('Evaluating Content Security Policy...');
  const csp = headers['content-security-policy'] || '';
  if (!csp) {
    results.checks.push({ category: 'CSP', name: 'Content-Security-Policy', status: 'fail', value: 'Not set' });
    results.findings.push({ id: 'VULN-CSP-MISSING', severity: 'high', title: 'No Content Security Policy',
      description: 'CSP header is missing, no protection against XSS and data injection.',
      module: 'vulnAssessment', remediation: "Add a Content-Security-Policy header. Start with: default-src 'self'" });
  } else {
    const issues = [];
    if (csp.includes("'unsafe-inline'")) issues.push("allows 'unsafe-inline'");
    if (csp.includes("'unsafe-eval'")) issues.push("allows 'unsafe-eval'");
    if (csp.includes('*')) issues.push('uses wildcard (*)');
    if (!csp.includes('default-src')) issues.push('missing default-src directive');
    const status = issues.length === 0 ? 'pass' : issues.length <= 1 ? 'warn' : 'fail';
    results.checks.push({ category: 'CSP', name: 'Content-Security-Policy', status, value: issues.length ? issues.join(', ') : 'Well configured' });
    if (issues.length) results.findings.push({ id: 'VULN-CSP-WEAK', severity: issues.length > 1 ? 'high' : 'medium',
      title: 'Weak Content Security Policy', description: `CSP issues: ${issues.join('; ')}.`,
      module: 'vulnAssessment', remediation: "Remove unsafe-inline/unsafe-eval, avoid wildcards, add default-src 'self'." });
  }

  // 4. CORS
  onProgress('Checking CORS configuration...');
  try {
    const r = await fetch(baseUrl, { signal: AbortSignal.timeout(8000),
      headers: { Origin: 'https://evil-test.com', 'User-Agent': 'Mozilla/5.0' } });
    const acao = r.headers.get('access-control-allow-origin') || '';
    const acac = r.headers.get('access-control-allow-credentials') || '';
    if (acao === '*') {
      results.checks.push({ category: 'CORS', name: 'Access-Control-Allow-Origin', status: 'fail', value: '*' });
      results.findings.push({ id: 'VULN-CORS-WILD', severity: acac ? 'critical' : 'medium',
        title: 'Wildcard CORS Policy', description: 'Server allows requests from any origin.',
        module: 'vulnAssessment', remediation: 'Restrict CORS to specific trusted origins.' });
    } else if (acao.includes('evil-test.com')) {
      results.checks.push({ category: 'CORS', name: 'Access-Control-Allow-Origin', status: 'fail', value: acao });
      results.findings.push({ id: 'VULN-CORS-REFLECT', severity: 'critical',
        title: 'CORS Origin Reflection', description: 'Server reflects arbitrary Origin header — full CORS bypass.',
        module: 'vulnAssessment', remediation: 'Whitelist specific trusted origins instead of reflecting.' });
    } else {
      results.checks.push({ category: 'CORS', name: 'CORS Policy', status: 'pass', value: acao || 'Not set (restrictive)' });
    }
  } catch (_) { results.checks.push({ category: 'CORS', name: 'CORS Policy', status: 'info', value: 'Could not test' }); }

  // 5. HTTPS Redirect
  onProgress('Checking HTTPS redirect...');
  try {
    const r = await fetch(`http://${domain}`, { redirect: 'manual', signal: AbortSignal.timeout(8000) });
    const loc = r.headers.get('location') || '';
    if (r.status >= 300 && r.status < 400 && loc.startsWith('https://')) {
      results.checks.push({ category: 'HTTPS', name: 'HTTP→HTTPS Redirect', status: 'pass', value: `${r.status} → ${loc}` });
    } else {
      results.checks.push({ category: 'HTTPS', name: 'HTTP→HTTPS Redirect', status: 'fail', value: `Status ${r.status}` });
      results.findings.push({ id: 'VULN-NO-HTTPS-REDIR', severity: 'high', title: 'No HTTPS Redirect',
        description: 'HTTP requests are not redirected to HTTPS.', module: 'vulnAssessment',
        remediation: 'Configure server to redirect all HTTP traffic to HTTPS (301).' });
    }
  } catch (_) { results.checks.push({ category: 'HTTPS', name: 'HTTP→HTTPS Redirect', status: 'info', value: 'Could not test' }); }

  // 6. HTTP Methods
  onProgress('Testing HTTP methods...');
  const dangerous = ['PUT', 'DELETE', 'TRACE', 'PATCH'];
  for (const method of dangerous) {
    try {
      const r = await fetch(baseUrl, { method, signal: AbortSignal.timeout(5000) });
      const allowed = r.status !== 405 && r.status !== 501 && r.status !== 403;
      results.checks.push({ category: 'HTTP Methods', name: method, status: allowed ? 'warn' : 'pass', value: `HTTP ${r.status}` });
      if (allowed) results.findings.push({ id: `VULN-METHOD-${method}`, severity: method === 'TRACE' ? 'high' : 'medium',
        title: `${method} Method Allowed`, description: `The ${method} HTTP method returned ${r.status}. This may be dangerous.`,
        module: 'vulnAssessment', remediation: `Disable the ${method} method if not required.` });
    } catch (_) {}
  }

  // 7. Sensitive Files
  onProgress('Probing for sensitive files (and detecting soft-404s)...');
  let hasSoft404 = false;
  try {
    const softCheck = await fetch(baseUrl + '/non-existent-random-' + Math.random().toString(36).substring(7), { method: 'GET', signal: AbortSignal.timeout(4000) });
    if (softCheck.status === 200) hasSoft404 = true;
  } catch (_) {}

  const sensitiveFiles = [
    // Critical secrets & config
    { path: '/.env',                  name: 'Environment File',         sev: 'critical', verify: 'DB_' },
    { path: '/.env.local',            name: 'Local Env File',           sev: 'critical', verify: 'DB_' },
    { path: '/.env.production',       name: 'Production Env File',      sev: 'critical', verify: 'DB_' },
    { path: '/.git/config',           name: 'Git Config',               sev: 'critical', verify: '[core]' },
    { path: '/.git/HEAD',             name: 'Git HEAD',                 sev: 'critical', verify: 'ref:' },
    { path: '/.htpasswd',             name: 'htpasswd File',            sev: 'critical', verify: ':' },
    // High severity
    { path: '/phpinfo.php',           name: 'PHP Info',                 sev: 'high', verify: '<title>phpinfo()' },
    { path: '/server-info',           name: 'Apache Server Info',       sev: 'high', verify: 'Apache Server Information' },
    { path: '/web.config',            name: 'IIS Config',               sev: 'high', verify: '<configuration>' },
    { path: '/package.json',          name: 'Node Package Manifest',    sev: 'high', verify: '"name":' },
    { path: '/composer.json',         name: 'Composer Manifest',        sev: 'high', verify: '"require":' },
    { path: '/docker-compose.yml',    name: 'Docker Compose File',      sev: 'high', verify: 'services:' },
    { path: '/api/swagger',           name: 'Swagger UI',               sev: 'high', verify: 'swagger' },
    // Admin panels
    { path: '/admin',                 name: 'Admin Panel',              sev: 'high', verify: 'admin' },
    { path: '/wp-login.php',          name: 'WordPress Login',          sev: 'high', verify: 'wp-submit' },
    { path: '/phpmyadmin',            name: 'phpMyAdmin',               sev: 'high', verify: 'pma' },
    { path: '/manager/html',          name: 'Tomcat Manager',           sev: 'high', verify: 'Tomcat' },
    { path: '/jenkins',               name: 'Jenkins',                  sev: 'high', verify: 'Jenkins' },
  ];
  const fileChecks = sensitiveFiles.map(async (f) => {
    try {
      // If the server has a soft 404, we MUST fetch the body (GET) to verify content, otherwise HEAD is faster.
      const method = (hasSoft404 && f.verify) ? 'GET' : 'HEAD';
      const r = await fetch(baseUrl + f.path, { method, signal: AbortSignal.timeout(4000), redirect: 'manual' });
      
      let found = false;
      // We only consider 200 OK as a hit (ignore 301/302 redirects to login or home pages)
      if (r.status === 200) {
        if (hasSoft404 && f.verify && method === 'GET') {
          const body = await r.text();
          if (body.toLowerCase().includes(f.verify.toLowerCase())) found = true;
        } else if (!hasSoft404) {
          found = true;
        }
      }

      if (found) {
        results.checks.push({ category: 'Sensitive Files', name: f.name, status: 'fail', value: `${f.path} → 200 OK` });
        results.findings.push({ id: `VULN-FILE-${f.name.replace(/\s+/g, '-').toUpperCase()}`, severity: f.sev,
          title: `Exposed: ${f.name}`, description: `${f.path} is publicly accessible (HTTP 200) and contains sensitive information.`,
          module: 'vulnAssessment', affected: baseUrl + f.path,
          remediation: `Remove ${f.path} from web root or block access at server level.` });
      }
    } catch (_) {}
  });
  await Promise.allSettled(fileChecks);

  // 8. SSL/TLS
  onProgress('Analyzing SSL/TLS certificate...');
  try {
    const certInfo = await getCertInfo(domain);
    if (certInfo) {
      const daysLeft = Math.floor((new Date(certInfo.validTo) - Date.now()) / 86400000);
      const expired = daysLeft < 0;
      results.checks.push({ category: 'SSL/TLS', name: 'Certificate Validity', status: expired ? 'fail' : daysLeft < 30 ? 'warn' : 'pass',
        value: expired ? `Expired ${-daysLeft} days ago` : `${daysLeft} days remaining` });
      results.checks.push({ category: 'SSL/TLS', name: 'Issuer', status: 'info', value: certInfo.issuer });
      results.checks.push({ category: 'SSL/TLS', name: 'Subject', status: 'info', value: certInfo.subject });
      if (expired) results.findings.push({ id: 'VULN-SSL-EXPIRED', severity: 'critical', title: 'SSL Certificate Expired',
        description: `Certificate expired ${-daysLeft} days ago.`, module: 'vulnAssessment', remediation: 'Renew the SSL certificate immediately.' });
      else if (daysLeft < 30) results.findings.push({ id: 'VULN-SSL-EXPIRING', severity: 'medium', title: 'SSL Certificate Expiring Soon',
        description: `Certificate expires in ${daysLeft} days.`, module: 'vulnAssessment', remediation: 'Renew the SSL certificate before it expires.' });
    }
  } catch (_) { results.checks.push({ category: 'SSL/TLS', name: 'Certificate', status: 'info', value: 'Could not retrieve' }); }

  // 9. Known CVE Matching
  onProgress('Matching detected software against known CVEs...');
  const serverHeader = headers['server'] || '';
  const poweredBy = headers['x-powered-by'] || '';
  const cveDB = [
    // Web Servers
    { pattern: /Apache\/2\.4\.49/i, cve: 'CVE-2021-41773', sev: 'critical', title: 'Apache Path Traversal', fix: 'Upgrade Apache to 2.4.51+' },
    { pattern: /Apache\/2\.4\.50/i, cve: 'CVE-2021-42013', sev: 'critical', title: 'Apache Path Traversal (Incomplete Fix)', fix: 'Upgrade Apache to 2.4.51+' },
    { pattern: /nginx\/1\.([0-9]|1[0-7])\./i, cve: 'CVE-2021-23017', sev: 'high', title: 'Nginx DNS Resolver Vulnerability', fix: 'Upgrade Nginx to 1.21.0+' },
    { pattern: /Microsoft-IIS\/([6-8])\./i, cve: 'CVE-2017-7269', sev: 'critical', title: 'IIS WebDAV Buffer Overflow', fix: 'Upgrade IIS and disable WebDAV' },
    { pattern: /openresty\/1\.1[0-5]/i, cve: 'CVE-2019-9511', sev: 'high', title: 'OpenResty HTTP/2 DoS', fix: 'Upgrade OpenResty' },
    // PHP
    { pattern: /PHP\/[5-7]\.[0-3]/i, cve: 'CVE-2019-11043', sev: 'critical', title: 'PHP-FPM Remote Code Execution', fix: 'Upgrade PHP to latest stable version' },
    { pattern: /PHP\/8\.0\./i, cve: 'CVE-2023-3247', sev: 'medium', title: 'PHP 8.0 Information Disclosure', fix: 'Upgrade to PHP 8.1+' },
    // Frameworks & Runtimes
    { pattern: /Express/i, cve: 'INFO', sev: 'low', title: 'Express.js Version Disclosed', fix: 'Disable X-Powered-By: app.disable("x-powered-by")' },
    { pattern: /JBoss/i, cve: 'CVE-2017-12149', sev: 'critical', title: 'JBoss Deserialization RCE', fix: 'Apply RedHat security patches' },
    { pattern: /Tomcat\/([4-9]|10)\./i, cve: 'CVE-2020-1938', sev: 'critical', title: 'Apache Tomcat Ghostcat (AJP)', fix: 'Disable AJP connector or upgrade Tomcat' },
    { pattern: /WebLogic/i, cve: 'CVE-2020-14882', sev: 'critical', title: 'Oracle WebLogic RCE', fix: 'Apply Oracle October 2020 CPU patches' },
    { pattern: /ColdFusion/i, cve: 'CVE-2023-26360', sev: 'critical', title: 'Adobe ColdFusion RCE', fix: 'Apply Adobe security updates' },
    // Log4j / Spring (detecting indicators in headers or errors)
    { pattern: /log4j/i, cve: 'CVE-2021-44228', sev: 'critical', title: 'Log4Shell (Log4j RCE)', fix: 'Upgrade log4j to 2.17.1+ or set formatMsgNoLookups=true' },
    { pattern: /Spring/i, cve: 'CVE-2022-22963', sev: 'critical', title: 'Spring4Shell RCE', fix: 'Upgrade Spring Cloud Function' },
    { pattern: /Struts/i, cve: 'CVE-2017-5638', sev: 'critical', title: 'Apache Struts 2 RCE', fix: 'Upgrade Apache Struts' },
    // Atlassian
    { pattern: /Confluence/i, cve: 'CVE-2022-26134', sev: 'critical', title: 'Confluence OGNL RCE', fix: 'Apply Atlassian security patches' },
    { pattern: /Jira/i, cve: 'CVE-2019-11581', sev: 'critical', title: 'Jira Template Injection', fix: 'Upgrade Jira Software' },
    { pattern: /Bitbucket/i, cve: 'CVE-2022-36804', sev: 'critical', title: 'Bitbucket Command Injection', fix: 'Apply Atlassian security patches' },
    // CI/CD & DevOps
    { pattern: /GitLab/i, cve: 'CVE-2021-22205', sev: 'critical', title: 'GitLab ExifTool RCE', fix: 'Upgrade GitLab' },
    { pattern: /Jenkins/i, cve: 'CVE-2024-23897', sev: 'critical', title: 'Jenkins CLI LFI/RCE', fix: 'Upgrade Jenkins and disable CLI' },
    { pattern: /Grafana\/8\.[0-3]/i, cve: 'CVE-2021-43798', sev: 'critical', title: 'Grafana LFI', fix: 'Upgrade Grafana to 8.3.1+' },
    // F5 / BIG-IP
    { pattern: /BIG-IP/i, cve: 'CVE-2020-5902', sev: 'critical', title: 'F5 BIG-IP TMUI RCE', fix: 'Apply F5 security patches' },
    { pattern: /BIG-IP/i, cve: 'CVE-2022-1388', sev: 'critical', title: 'F5 BIG-IP iControl RCE', fix: 'Apply F5 security patches' },
    // VPNs & Gateways
    { pattern: /Pulse Secure/i, cve: 'CVE-2019-11510', sev: 'critical', title: 'Pulse Secure LFI', fix: 'Apply Ivanti security patches' },
    { pattern: /GlobalProtect/i, cve: 'CVE-2019-1579', sev: 'critical', title: 'Palo Alto GlobalProtect RCE', fix: 'Apply Palo Alto security patches' },
    { pattern: /Fortinet/i, cve: 'CVE-2018-13379', sev: 'critical', title: 'Fortinet FortiOS LFI', fix: 'Apply Fortinet security patches' },
    { pattern: /Fortinet/i, cve: 'CVE-2023-27997', sev: 'critical', title: 'FortiOS Heap Overflow RCE', fix: 'Apply Fortinet security patches' },
    { pattern: /Citrix/i, cve: 'CVE-2019-19781', sev: 'critical', title: 'Citrix ADC / NetScaler RCE', fix: 'Apply Citrix security patches' },
    { pattern: /Citrix/i, cve: 'CVE-2023-3519', sev: 'critical', title: 'Citrix NetScaler RCE', fix: 'Apply Citrix security patches' },
    // Additional CMS
    { pattern: /vBulletin/i, cve: 'CVE-2019-16759', sev: 'critical', title: 'vBulletin RCE', fix: 'Apply vBulletin security patches' },
    { pattern: /Drupal/i, cve: 'CVE-2018-7600', sev: 'critical', title: 'Drupalgeddon 2 RCE', fix: 'Upgrade Drupal' },
    { pattern: /Magento/i, cve: 'CVE-2022-24086', sev: 'critical', title: 'Magento Improper Input Validation', fix: 'Apply Adobe Commerce patches' },
    { pattern: /Ghost/i, cve: 'CVE-2021-29484', sev: 'high', title: 'Ghost CMS XSS', fix: 'Upgrade Ghost' },
    // General / Others
    { pattern: /Webmin\/1\.920/i, cve: 'CVE-2019-15107', sev: 'critical', title: 'Webmin RCE', fix: 'Upgrade Webmin' },
    { pattern: /Liferay/i, cve: 'CVE-2020-7961', sev: 'critical', title: 'Liferay Portal RCE', fix: 'Apply Liferay patches' },
    { pattern: /Cisco/i, cve: 'CVE-2020-3452', sev: 'high', title: 'Cisco ASA LFI', fix: 'Apply Cisco patches' },
    { pattern: /Splunk/i, cve: 'CVE-2023-46214', sev: 'critical', title: 'Splunk Enterprise RCE', fix: 'Upgrade Splunk' },
  ];
  const combined = `${serverHeader} ${poweredBy}`;
  for (const entry of cveDB) {
    if (entry.pattern.test(combined)) {
      results.checks.push({ category: 'Known CVEs', name: entry.cve, status: 'fail', value: entry.title });
      results.findings.push({ id: `VULN-CVE-${entry.cve}`, severity: entry.sev, title: `${entry.cve}: ${entry.title}`,
        description: `Detected vulnerable software version. Server: "${combined.trim()}"`,
        module: 'vulnAssessment', remediation: entry.fix });
    }
  }
  if (!results.checks.some(c => c.category === 'Known CVEs'))
    results.checks.push({ category: 'Known CVEs', name: 'Version Check', status: 'pass', value: 'No known CVEs matched' });

  // 10. CSRF Detection
  onProgress('Checking for CSRF protection...');
  const formRegex = /<form[^>]*method\s*=\s*["']?post["']?[^>]*>([\s\S]*?)<\/form>/gi;
  let formMatch, formCount = 0, unprotected = 0;
  while ((formMatch = formRegex.exec(html)) !== null) {
    formCount++;
    const body = formMatch[1];
    const hasToken = /csrf|_token|authenticity_token|__RequestVerificationToken/i.test(body);
    if (!hasToken) unprotected++;
  }
  if (formCount > 0) {
    results.checks.push({ category: 'CSRF', name: 'Form Protection', status: unprotected > 0 ? 'fail' : 'pass',
      value: `${formCount - unprotected}/${formCount} forms protected` });
    if (unprotected > 0) results.findings.push({ id: 'VULN-CSRF', severity: 'medium',
      title: `${unprotected} Form(s) Without CSRF Protection`,
      description: `Found ${unprotected} POST form(s) without visible CSRF tokens.`,
      module: 'vulnAssessment', remediation: 'Add CSRF tokens to all state-changing forms.' });
  } else {
    results.checks.push({ category: 'CSRF', name: 'Form Protection', status: 'info', value: 'No POST forms found' });
  }

  // 11a. JWT in Cookies
  onProgress('Checking for JWT tokens in cookies...');
  const jwtRe = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/;
  if (jwtRe.test(cookieStr)) {
    results.checks.push({ category: 'JWT', name: 'JWT in Cookie', status: 'warn', value: 'JWT detected in Set-Cookie header' });
    results.findings.push({ id: 'VULN-JWT-COOKIE', severity: 'medium',
      title: 'JWT Token Stored in Cookie',
      description: 'A JWT token was detected in a Set-Cookie header. Ensure the cookie has Secure, HttpOnly, and SameSite=Strict flags, and that JWT signatures use strong algorithms (RS256/ES256, not HS256 with weak secrets).',
      module: 'vulnAssessment',
      remediation: 'Use RS256 or ES256 for JWT signing. Ensure cookies carrying JWTs have Secure + HttpOnly + SameSite=Strict flags. Implement short expiry times.' });
  } else {
    results.checks.push({ category: 'JWT', name: 'JWT in Cookie', status: 'pass', value: 'No JWT detected in cookies' });
  }

  // 11. Open Redirect
  onProgress('Testing for open redirect indicators...');
  const redirectParams = ['url', 'redirect', 'next', 'return', 'returnUrl', 'goto', 'redirect_uri', 'continue'];
  let redirectVuln = false;
  for (const param of redirectParams.slice(0, 4)) {
    try {
      const testUrl = `${baseUrl}/?${param}=https://evil.com`;
      const r = await fetch(testUrl, { redirect: 'manual', signal: AbortSignal.timeout(4000) });
      const loc = (r.headers.get('location') || '').toLowerCase();
      if (loc.includes('evil.com')) {
        redirectVuln = true;
        results.findings.push({ id: `VULN-REDIR-${param}`, severity: 'medium', title: `Open Redirect via "${param}" Parameter`,
          description: `The "${param}" parameter redirects to arbitrary URLs.`,
          module: 'vulnAssessment', remediation: 'Validate redirect URLs against a whitelist of allowed domains.' });
        break;
      }
    } catch (_) {}
  }
  results.checks.push({ category: 'Open Redirect', name: 'Redirect Parameters', status: redirectVuln ? 'fail' : 'pass',
    value: redirectVuln ? 'Vulnerable' : 'No open redirects detected' });

  // 12. Directory Listing
  onProgress('Checking for directory listing...');
  const dirs = ['/images/', '/css/', '/js/', '/assets/', '/uploads/', '/static/', '/media/'];
  let dirListing = false;
  for (const dir of dirs) {
    try {
      const r = await fetch(baseUrl + dir, { signal: AbortSignal.timeout(4000) });
      if (r.status === 200) {
        const body = await r.text();
        if (/Index of|Directory listing|Parent Directory|\[To Parent Directory\]/i.test(body)) {
          dirListing = true;
          results.findings.push({ id: `VULN-DIRLIST-${dir.replace(/\//g, '')}`, severity: 'medium',
            title: `Directory Listing Enabled: ${dir}`, description: `Directory index is visible at ${dir}.`,
            module: 'vulnAssessment', affected: baseUrl + dir, remediation: 'Disable directory listing in web server config.' });
          break;
        }
      }
    } catch (_) {}
  }
  results.checks.push({ category: 'Directory Listing', name: 'Index Pages', status: dirListing ? 'fail' : 'pass',
    value: dirListing ? 'Enabled on some directories' : 'Not detected' });

  // Build summary
  for (const c of results.checks) {
    if (c.status === 'pass') results.summary.pass++;
    else if (c.status === 'fail') results.summary.fail++;
    else if (c.status === 'warn') results.summary.warn++;
    else results.summary.info++;
  }

  onProgress(`Vulnerability assessment complete — ${results.findings.length} issues found`);
  return results;
}

function getCertInfo(domain) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => { reject(new Error('SSL timeout')); }, 8000);
    try {
      const sock = tls.connect(443, domain, { servername: domain, rejectUnauthorized: false }, () => {
        clearTimeout(timeout);
        try {
          const cert = sock.getPeerCertificate();
          sock.destroy();
          if (!cert || !cert.valid_from) return resolve(null);
          resolve({ subject: cert.subject?.CN || '', issuer: cert.issuer?.O || cert.issuer?.CN || '',
            validFrom: cert.valid_from, validTo: cert.valid_to, protocol: sock.getProtocol() });
        } catch (e) { sock.destroy(); resolve(null); }
      });
      sock.on('error', () => { clearTimeout(timeout); reject(new Error('TLS error')); });
    } catch (e) { clearTimeout(timeout); reject(e); }
  });
}

module.exports = { runVulnAssessment };
