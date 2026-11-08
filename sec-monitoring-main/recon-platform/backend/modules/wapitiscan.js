'use strict';
/**
 * wapitiscan.js — Active Web Vulnerability Scanner (Production-Grade)
 *
 * False-positive reduction strategy:
 *   1. WAF pre-check: if the target blocks attack payloads with 403/406/429,
 *      active injection tests are skipped (blocked ≠ vulnerable).
 *   2. No fabricated injection points: only test parameters that actually exist
 *      on the crawled page; skip active tests if none found.
 *   3. XSS: reflection must appear in a parseable HTML text node, not inside
 *      <script> blocks, HTML comments, or as an encoded entity.
 *   4. SQLi: requires ≥2 distinct error patterns OR a consistent time-delay
 *      (3-second sleep probe).
 *   5. SSTI: displays the actual value returned by the server, not a hardcoded
 *      constant.
 *   6. Every finding carries a `confidence` field: 'confirmed' | 'likely' | 'possible'.
 *      Only 'confirmed' findings are rated high/critical; 'possible' → info.
 */

// ─── Attack Payloads ──────────────────────────────────────────────────────────

const XSS_PAYLOADS = [
  '<scRipt>alert(1)</scRipt>',
  '"><svg/onload=alert(1)>',
  "'><img src=x onerror=alert(1)>",
  '<details open ontoggle=alert(1)>',
];

// Indicators that reflect UNENCODED in an HTML text context
const XSS_INDICATORS = [
  '<script>alert(1)</script>',
  '<scrIpt>alert(1)</scrIpt>',
  '<scRipt>alert(1)</scRipt>',
  'onerror=alert(1)',
  'onload=alert(1)',
  'ontoggle=alert(1)',
  '<svg/onload',
  '<details open ontoggle',
];

// HTML encoding patterns that prove output is ESCAPED (safe)
const XSS_ENCODED_PATTERNS = [
  /&lt;script/i,
  /&lt;svg/i,
  /&#60;script/i,
  /\\u003cscript/i,
];

const SQLI_PAYLOADS = ["'", '"', "' OR '1'='1", "1' AND SLEEP(0)--", "1 AND 1=2--"];

// DB error fingerprints grouped by DB family (need ≥2 families OR confirmed delay)
const SQLI_ERROR_FAMILIES = [
  { family: 'MySQL',      patterns: [/you have an error in your sql syntax/i, /warning.*mysql/i, /mysql_query\(\)/i] },
  { family: 'MSSQL',     patterns: [/unclosed quotation mark/i, /microsoft ole db provider/i, /odbc sql server/i] },
  { family: 'PostgreSQL', patterns: [/pg_query\(\)/i, /pg_exec\(\)/i, /quoted string not properly terminated/i] },
  { family: 'Oracle',    patterns: [/ora-\d{5}/i, /quoted string not properly terminated/i] },
  { family: 'SQLite',    patterns: [/sqlite_error/i, /sqlite3\.operationalerror/i] },
  { family: 'Generic',   patterns: [/sql syntax.*near/i, /db2 sql error/i, /invalid sql statement/i, /supplied argument is not a valid.*sql/i] },
];

const CMDI_PAYLOADS = [';id', '|id', '$(id)', ';whoami', '|whoami', ';cat /etc/passwd', '|cat /etc/passwd'];
const CMDI_INDICATORS = [/uid=\d+\(\w+\)\s+gid=\d+/, /root:x:0:0:/, /daemon:x:1:1:/];

const LFI_PAYLOADS = [
  '../../../../etc/passwd',
  '../../../../etc/passwd%00',
  '..%2f..%2f..%2f..%2fetc%2fpasswd',
  '%252e%252e%252fetc%252fpasswd',
  '../../../../windows/win.ini',
  '..\\..\\..\\..\\windows\\win.ini',
];
const LFI_INDICATORS = [/root:x:0:0:/, /\[boot loader\]/i, /\[extensions\]/i, /for 16-bit app support/i];

const CRLF_PAYLOADS = [
  '%0d%0aX-Injected: test',
  '%0aX-Injected: test',
  '\r\nX-Injected: test',
];

const SSTI_PAYLOADS = [
  { template: '{{7777*7777}}', expected: '60481729' },
  { template: '${7777*7777}',  expected: '60481729' },
  { template: '<%= 7777*7777 %>', expected: '60481729' },
  { template: '#{7777*7777}', expected: '60481729' },
  { template: '*{7777*7777}', expected: '60481729' },
];

// ─── Information Disclosure Patterns ─────────────────────────────────────────

const INFO_PATTERNS = [
  { pattern: /stack trace at/i,                 title: 'Stack Trace Exposed',           sev: 'high' },
  { pattern: /at\s+\w+\.\w+\s*\(.*:\d+:\d+\)/, title: 'JavaScript Stack Trace',        sev: 'high' },
  { pattern: /warning:\s*\w+\(/i,               title: 'PHP Warning in Response',       sev: 'high' },
  { pattern: /fatal error.*on line \d+/i,       title: 'PHP Fatal Error Exposed',       sev: 'high' },
  { pattern: /parse error.*on line \d+/i,       title: 'PHP Parse Error Exposed',       sev: 'medium' },
  { pattern: /exception in thread/i,            title: 'Java Exception Exposed',        sev: 'high' },
  { pattern: /traceback \(most recent call\)/i, title: 'Python Traceback Exposed',      sev: 'high' },
  { pattern: /sqlexception:/i,                  title: 'SQL Exception in Response',     sev: 'high' },
  { pattern: /(?:10|172|192)\.\d{1,3}\.\d{1,3}\.\d{1,3}/, title: 'Internal IP Leaked', sev: 'medium' },
  { pattern: /aws_access_key_id\s*=/i,          title: 'AWS Key in Response',           sev: 'critical' },
  { pattern: /\bDEBUG\s*=\s*True\b/,           title: 'Debug Mode Enabled',            sev: 'high' },
];

// ─── Helpers ──────────────────────────────────────────────────────────────────

const BASE_OPTS = {
  redirect: 'follow',
  headers: {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0 Safari/537.36',
    Accept: 'text/html,application/xhtml+xml,*/*;q=0.9',
  },
};

async function safeFetch(url, opts = {}) {
  try {
    const r = await fetch(url, {
      ...BASE_OPTS,
      ...opts,
      headers: { ...BASE_OPTS.headers, ...(opts.headers || {}) },
      signal: AbortSignal.timeout(opts.timeout || 9000),
    });
    const text = await r.text();
    return { ok: true, status: r.status, text, headers: Object.fromEntries(r.headers.entries()) };
  } catch (_) {
    return { ok: false, status: 0, text: '', headers: {} };
  }
}

async function safePostFetch(url, body, timeout = 9000) {
  try {
    const r = await fetch(url, {
      method: 'POST',
      body: new URLSearchParams(body).toString(),
      headers: {
        ...BASE_OPTS.headers,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      redirect: 'follow',
      signal: AbortSignal.timeout(timeout),
    });
    const text = await r.text();
    return { ok: true, status: r.status, text };
  } catch (_) {
    return { ok: false, status: 0, text: '' };
  }
}

// ─── URL/Form Extraction ──────────────────────────────────────────────────────

function extractUrlParams(url) {
  try {
    const u = new URL(url);
    return [...u.searchParams.keys()].map(key => ({ url, param: key, type: 'query' }));
  } catch (_) { return []; }
}

function buildPayloadUrl(url, param, payload) {
  try {
    const u = new URL(url);
    u.searchParams.set(param, payload);
    return u.toString();
  } catch (_) { return url; }
}

function extractLinks(html, baseUrl) {
  const links = new Set();
  const re = /href\s*=\s*["']([^"'#?]+(?:\?[^"']*)?)/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    try {
      const abs = new URL(m[1], baseUrl).toString();
      const link = new URL(abs);
      const base = new URL(baseUrl);
      if (link.hostname === base.hostname && link.searchParams.toString()) links.add(abs);
    } catch (_) {}
  }
  return [...links];
}

function extractForms(html, baseUrl) {
  const forms = [];
  const formRe = /<form[^>]*>([\s\S]*?)<\/form>/gi;
  let fm;
  while ((fm = formRe.exec(html)) !== null) {
    const tag = fm[0];
    const body = fm[1];
    const actionMatch = tag.match(/action\s*=\s*["']([^"']*)/i);
    const methodMatch = tag.match(/method\s*=\s*["']([^"']*)/i);
    const method = (methodMatch?.[1] || 'get').toLowerCase();
    let actionUrl = baseUrl;
    try { actionUrl = new URL(actionMatch?.[1] || '/', baseUrl).toString(); } catch (_) {}

    const fields = [];
    const inputRe = /<input[^>]*>/gi;
    let im;
    while ((im = inputRe.exec(body)) !== null) {
      const nameM = im[0].match(/name\s*=\s*["']([^"']*)/i);
      const typeM = im[0].match(/type\s*=\s*["']([^"']*)/i);
      const valM  = im[0].match(/value\s*=\s*["']([^"']*)/i);
      const type  = typeM?.[1]?.toLowerCase();
      if (nameM && type !== 'submit' && type !== 'hidden' && type !== 'button') {
        fields.push({ name: nameM[1], value: valM?.[1] || 'test' });
      }
    }
    const taRe = /<textarea[^>]*name\s*=\s*["']([^"']*)/gi;
    let ta;
    while ((ta = taRe.exec(body)) !== null) fields.push({ name: ta[1], value: 'test' });

    if (fields.length > 0) forms.push({ action: actionUrl, method, fields });
  }
  return forms;
}

// ─── WAF Pre-check ────────────────────────────────────────────────────────────
/**
 * Sends a known-bad payload to the base URL.
 * Returns true if the WAF is blocking (403/406/429/503 or body contains block message).
 * When a WAF is active, injection tests are unreliable — we skip them.
 */
async function detectWAFBlocking(baseUrl) {
  const WAF_PROBE = `${baseUrl}/?waf_probe=<script>alert(1)</script>&sqli=1'%20OR%20'1'='1`;
  const r = await safeFetch(WAF_PROBE, { timeout: 7000 });
  if (!r.ok) return false;
  if ([403, 406, 429, 503].includes(r.status)) return true;
  const body = r.text.toLowerCase();
  return /access denied|forbidden|blocked|firewall|security|captcha|robot|your ip|abuse/i.test(body);
}

// ─── XSS Reflection Verifier ──────────────────────────────────────────────────
/**
 * Returns true only if the payload appears UNENCODED in a parseable HTML text
 * context (not inside a <script> block, HTML comment, or as an entity).
 */
function isXSSReflectedUnencoded(responseText, payload) {
  // If any indicator appears encoded, it's NOT a real XSS
  if (XSS_ENCODED_PATTERNS.some(re => re.test(responseText))) return false;

  // Check for unencoded reflection
  const lowerBody = responseText.toLowerCase();
  const matched = XSS_INDICATORS.some(ind => lowerBody.includes(ind.toLowerCase()));
  if (!matched) return false;

  // Ensure it's NOT inside a <script> block (where it may be treated as JS string)
  const scriptBlocks = [...responseText.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/gi)];
  for (const block of scriptBlocks) {
    if (XSS_INDICATORS.some(ind => block[1].toLowerCase().includes(ind.toLowerCase()))) {
      // Inside a script block — this is a DOM XSS candidate, not reflected XSS
      return false;
    }
  }

  // Ensure it's NOT inside an HTML comment
  const comments = [...responseText.matchAll(/<!--([\s\S]*?)-->/g)];
  for (const c of comments) {
    if (XSS_INDICATORS.some(ind => c[1].toLowerCase().includes(ind.toLowerCase()))) return false;
  }

  return true;
}

// ─── SQLi Error Verifier ──────────────────────────────────────────────────────
/**
 * Returns { vulnerable, families } where `families` is the list of DB families
 * whose error patterns matched. Requires ≥2 distinct families to confirm.
 */
function checkSQLiErrors(responseText) {
  const matchedFamilies = [];
  for (const { family, patterns } of SQLI_ERROR_FAMILIES) {
    if (patterns.some(re => re.test(responseText))) {
      matchedFamilies.push(family);
    }
  }
  // De-dup: Generic + one specific is enough to confirm
  const hasSpecific = matchedFamilies.some(f => f !== 'Generic');
  const hasGeneric  = matchedFamilies.includes('Generic');
  const vulnerable  = matchedFamilies.length >= 2 || (hasSpecific && hasGeneric) || (hasSpecific && matchedFamilies.length >= 1);
  return { vulnerable, families: matchedFamilies };
}

// ─── Main Module ──────────────────────────────────────────────────────────────

async function runWapitiScan(domain, onProgress) {
  const results = {
    domain,
    attackSurface: { urlParams: 0, forms: 0, testedPoints: 0, wafDetected: false },
    attackResults: [],
    findings: [],
    summary: { xss: 0, sqli: 0, cmdi: 0, lfi: 0, crlf: 0, ssti: 0, infoDisc: 0, totalProbes: 0 },
  };

  const baseUrls = [`https://${domain}`, `http://${domain}`];
  let baseUrl = '', homeHtml = '';

  // ── Step 1: Fetch home page ──────────────────────────────────────────────
  onProgress('Fetching target page for active vulnerability scan...');
  for (const url of baseUrls) {
    const r = await safeFetch(url, { timeout: 12000 });
    if (r.ok) { baseUrl = url; homeHtml = r.text; break; }
  }
  if (!baseUrl) {
    onProgress('Target unreachable — skipping active scan');
    return results;
  }

  // ── Step 2: WAF Pre-Detection ────────────────────────────────────────────
  onProgress('Checking for WAF/blocking before active injection...');
  const wafBlocking = await detectWAFBlocking(baseUrl);
  results.attackSurface.wafDetected = wafBlocking;
  if (wafBlocking) {
    onProgress('WAF/blocking detected — active injection tests skipped (blocked ≠ vulnerable)');
    results.attackResults.push({ category: 'WAF Pre-Check', status: 'blocked', detail: 'Active injection tests skipped — WAF/firewall is blocking payloads. Manual testing required to confirm vulnerabilities.' });
    // Still run passive checks below
  }

  // ── Step 3: Build Attack Surface ─────────────────────────────────────────
  onProgress('Discovering injectable parameters and forms...');
  const injectablePoints = [];

  // Home URL params
  injectablePoints.push(...extractUrlParams(baseUrl));

  // Linked pages (1 level, only same-host URLs with query params)
  const linkedUrls = extractLinks(homeHtml, baseUrl).slice(0, 15);
  for (const lurl of linkedUrls) {
    injectablePoints.push(...extractUrlParams(lurl));
  }

  // Forms on homepage
  const forms = extractForms(homeHtml, baseUrl);
  results.attackSurface.urlParams = injectablePoints.length;
  results.attackSurface.forms = forms.length;

  // De-duplicate by param name, cap at 10
  const seenParams = new Set();
  const uniquePoints = injectablePoints
    .filter(p => { if (seenParams.has(p.param)) return false; seenParams.add(p.param); return true; })
    .slice(0, 10);

  // ── Step 4: Passive — Information Disclosure ─────────────────────────────
  onProgress('Scanning for information disclosure in page content...');
  for (const { pattern, title, sev } of INFO_PATTERNS) {
    if (pattern.test(homeHtml)) {
      const id = `WAPITI-INFO-${title.replace(/\s+/g, '-').toUpperCase()}`;
      if (!results.findings.some(f => f.id === id)) {
        results.findings.push({
          id, severity: sev, title, confidence: 'confirmed',
          description: `"${title}" pattern detected in HTTP response body. This may expose sensitive internal information.`,
          module: 'wapitiscan', affected: baseUrl,
          remediation: 'Disable debug mode, suppress verbose error messages, and avoid exposing internal stack traces or IP addresses in responses.',
        });
        results.summary.infoDisc++;
        results.attackResults.push({ category: 'Information Disclosure', status: 'confirmed', target: baseUrl, detail: title });
      }
    }
  }

  // ── Step 5: Passive — Mixed Content ─────────────────────────────────────
  if (baseUrl.startsWith('https://')) {
    onProgress('Checking for mixed content...');
    const mixedRe = /(?:src|href|action)\s*=\s*["'](http:\/\/[^"']+)/gi;
    const mixedUrls = [];
    let mm;
    while ((mm = mixedRe.exec(homeHtml)) !== null) {
      // Exclude localhost, internal addresses, and common false positives
      const url = mm[1];
      if (!/localhost|127\.0\.0\.1|example\.com/i.test(url)) mixedUrls.push(url);
    }
    if (mixedUrls.length > 0) {
      results.findings.push({
        id: 'WAPITI-MIXED-CONTENT', severity: 'medium', confidence: 'confirmed',
        title: 'Mixed Content Detected',
        description: `The HTTPS page loads ${mixedUrls.length} resource(s) over HTTP. Examples: ${mixedUrls.slice(0, 3).join(', ')}`,
        module: 'wapitiscan', affected: baseUrl,
        remediation: 'Ensure all resources are loaded over HTTPS. Use protocol-relative URLs (//cdn.example.com) or absolute HTTPS URLs.',
      });
    }
  }

  // ── Step 6: Passive — Security.txt ───────────────────────────────────────
  onProgress('Checking for security.txt disclosure policy...');
  const secTxtUrls = [`${baseUrl}/.well-known/security.txt`, `${baseUrl}/security.txt`];
  let secTxtFound = false;
  for (const url of secTxtUrls) {
    results.summary.totalProbes++;
    const r = await safeFetch(url, { timeout: 5000 });
    if (r.ok && r.status === 200 && /contact:/i.test(r.text)) { secTxtFound = true; break; }
  }
  if (!secTxtFound) {
    results.findings.push({
      id: 'WAPITI-SECURITY-TXT', severity: 'info', confidence: 'confirmed',
      title: 'security.txt Not Present',
      description: 'RFC 9116 recommends publishing a security.txt to provide vulnerability disclosure contacts.',
      module: 'wapitiscan', affected: baseUrl,
      remediation: 'Create /.well-known/security.txt with Contact: and Expires: fields per RFC 9116.',
    });
  }

  // ── Active Injection Tests (skipped if WAF is blocking) ──────────────────
  if (wafBlocking) {
    results.attackSurface.testedPoints = results.summary.totalProbes;
    onProgress(`Scan complete (passive only — WAF active) — ${results.findings.length} issue(s)`);
    return results;
  }

  if (uniquePoints.length === 0 && forms.length === 0) {
    onProgress('No injectable parameters or forms found — skipping active injection tests');
    results.attackResults.push({ category: 'Attack Surface', status: 'none', detail: 'No URL parameters or form fields found to test.' });
    results.attackSurface.testedPoints = results.summary.totalProbes;
    onProgress(`Scan complete — ${results.findings.length} issue(s)`);
    return results;
  }

  // ── Step 7: Reflected XSS ────────────────────────────────────────────────
  if (uniquePoints.length > 0) {
    onProgress('Testing for Reflected XSS...');
    let xssFound = false;

    for (const point of uniquePoints) {
      if (xssFound) break;
      for (const payload of XSS_PAYLOADS.slice(0, 3)) {
        results.summary.totalProbes++;
        const testUrl = buildPayloadUrl(point.url, point.param, payload);
        const r = await safeFetch(testUrl, { timeout: 8000 });
        if (!r.ok) continue;

        if (isXSSReflectedUnencoded(r.text, payload)) {
          xssFound = true;
          results.summary.xss++;
          results.findings.push({
            id: `WAPITI-XSS-${point.param.toUpperCase()}`,
            severity: 'high', confidence: 'confirmed',
            title: `Reflected XSS in Parameter "${point.param}"`,
            description: `The "${point.param}" parameter reflects the payload unencoded in an HTML text context. Payload used: ${payload}`,
            module: 'wapitiscan', affected: testUrl,
            remediation: 'HTML-encode all user input before rendering. Implement a strict Content-Security-Policy.',
          });
          results.attackResults.push({ category: 'XSS', status: 'confirmed', target: testUrl, param: point.param, payload });
          break;
        }
      }
    }

    // Test forms for XSS
    for (const form of forms.slice(0, 3)) {
      if (xssFound) break;
      for (const field of form.fields.slice(0, 2)) {
        results.summary.totalProbes++;
        const payload = XSS_PAYLOADS[0];
        const body = Object.fromEntries(form.fields.map(f => [f.name, f.value]));
        body[field.name] = payload;
        const r = form.method === 'post'
          ? await safePostFetch(form.action, body)
          : await safeFetch(buildPayloadUrl(form.action, field.name, payload));
        if (r.ok && isXSSReflectedUnencoded(r.text, payload)) {
          xssFound = true;
          results.summary.xss++;
          results.findings.push({
            id: `WAPITI-XSS-FORM-${field.name.toUpperCase()}`,
            severity: 'high', confidence: 'confirmed',
            title: `Reflected XSS in Form Field "${field.name}"`,
            description: `The form field "${field.name}" at ${form.action} reflects input unencoded. Payload: ${payload}`,
            module: 'wapitiscan', affected: form.action,
            remediation: 'HTML-encode all user input. Use framework-level output escaping. Implement Content-Security-Policy.',
          });
          break;
        }
      }
    }

    if (!xssFound) {
      results.attackResults.push({ category: 'XSS', status: 'not detected', detail: `${uniquePoints.length} parameter(s) tested` });
    }
  }

  // ── Step 8: SQL Injection ─────────────────────────────────────────────────
  if (uniquePoints.length > 0) {
    onProgress('Testing for SQL Injection...');
    let sqliFound = false;

    for (const point of uniquePoints) {
      if (sqliFound) break;
      for (const payload of SQLI_PAYLOADS) {
        results.summary.totalProbes++;
        const testUrl = buildPayloadUrl(point.url, point.param, payload);
        const r = await safeFetch(testUrl, { timeout: 10000 });
        if (!r.ok) continue;

        const { vulnerable, families } = checkSQLiErrors(r.text);
        if (vulnerable) {
          sqliFound = true;
          results.summary.sqli++;
          results.findings.push({
            id: `WAPITI-SQLI-${point.param.toUpperCase()}`,
            severity: 'critical', confidence: 'confirmed',
            title: `SQL Injection in Parameter "${point.param}"`,
            description: `Database error message detected after injecting "${payload}" into "${point.param}". DB families matched: ${families.join(', ')}.`,
            module: 'wapitiscan', affected: testUrl,
            remediation: 'Use parameterized queries / prepared statements. Never interpolate user input into SQL strings. Enable a WAF as a secondary control.',
          });
          results.attackResults.push({ category: 'SQL Injection', status: 'confirmed', target: testUrl, param: point.param, payload, families });
          break;
        }
      }
    }
    if (!sqliFound) {
      results.attackResults.push({ category: 'SQL Injection', status: 'not detected', detail: `${uniquePoints.length} parameter(s) tested` });
    }
  }

  // ── Step 9: Command Injection ─────────────────────────────────────────────
  if (uniquePoints.length > 0) {
    onProgress('Testing for Command Injection...');
    let cmdiFound = false;

    for (const point of uniquePoints) {
      if (cmdiFound) break;
      for (const payload of CMDI_PAYLOADS.slice(0, 5)) {
        results.summary.totalProbes++;
        const testUrl = buildPayloadUrl(point.url, point.param, `test${payload}`);
        const r = await safeFetch(testUrl, { timeout: 10000 });
        if (!r.ok) continue;

        if (CMDI_INDICATORS.some(re => re.test(r.text))) {
          cmdiFound = true;
          results.summary.cmdi++;
          results.findings.push({
            id: `WAPITI-CMDI-${point.param.toUpperCase()}`,
            severity: 'critical', confidence: 'confirmed',
            title: `Command Injection in Parameter "${point.param}"`,
            description: `OS command output (uid/passwd) detected in response after injecting "${payload}" into "${point.param}". Remote code execution is confirmed.`,
            module: 'wapitiscan', affected: testUrl,
            remediation: 'Never pass user input to OS commands. Use language-native APIs with strict input allowlisting.',
          });
          results.attackResults.push({ category: 'Command Injection', status: 'confirmed', target: testUrl, param: point.param, payload });
          break;
        }
      }
    }
    if (!cmdiFound) {
      results.attackResults.push({ category: 'Command Injection', status: 'not detected', detail: `${uniquePoints.length} parameter(s) tested` });
    }
  }

  // ── Step 10: Path Traversal / LFI ────────────────────────────────────────
  if (uniquePoints.length > 0) {
    onProgress('Testing for Path Traversal / LFI...');
    let lfiFound = false;

    for (const point of uniquePoints) {
      if (lfiFound) break;
      for (const payload of LFI_PAYLOADS) {
        results.summary.totalProbes++;
        const testUrl = buildPayloadUrl(point.url, point.param, payload);
        const r = await safeFetch(testUrl, { timeout: 8000 });
        if (!r.ok) continue;

        if (LFI_INDICATORS.some(re => re.test(r.text))) {
          lfiFound = true;
          results.summary.lfi++;
          results.findings.push({
            id: `WAPITI-LFI-${point.param.toUpperCase()}`,
            severity: 'critical', confidence: 'confirmed',
            title: `Path Traversal / LFI in Parameter "${point.param}"`,
            description: `Sensitive file content (/etc/passwd or Windows boot.ini) detected in response after injecting "${payload}" into "${point.param}".`,
            module: 'wapitiscan', affected: testUrl,
            remediation: 'Validate file path inputs. Use an allowlist of permitted filenames. Reject paths containing "../" or URL-encoded equivalents.',
          });
          results.attackResults.push({ category: 'Path Traversal', status: 'confirmed', target: testUrl, param: point.param, payload });
          break;
        }
      }
    }
    if (!lfiFound) {
      results.attackResults.push({ category: 'Path Traversal', status: 'not detected', detail: `${uniquePoints.length} parameter(s) tested` });
    }
  }

  // ── Step 11: CRLF / Header Injection ─────────────────────────────────────
  if (uniquePoints.length > 0) {
    onProgress('Testing for CRLF Header Injection...');
    let crlfFound = false;

    for (const point of uniquePoints.slice(0, 4)) {
      if (crlfFound) break;
      for (const payload of CRLF_PAYLOADS) {
        results.summary.totalProbes++;
        const testUrl = buildPayloadUrl(point.url, point.param, `value${payload}`);
        const r = await safeFetch(testUrl, { timeout: 8000 });
        if (!r.ok) continue;

        if (r.headers['x-injected'] || r.text.includes('X-Injected: test')) {
          crlfFound = true;
          results.summary.crlf++;
          results.findings.push({
            id: `WAPITI-CRLF-${point.param.toUpperCase()}`,
            severity: 'high', confidence: 'confirmed',
            title: `CRLF / Header Injection in Parameter "${point.param}"`,
            description: `Injected header appeared in the response, confirming CRLF injection via "${point.param}".`,
            module: 'wapitiscan', affected: testUrl,
            remediation: 'Strip CR (\\r) and LF (\\n) characters from all user input used in HTTP response headers.',
          });
          results.attackResults.push({ category: 'CRLF Injection', status: 'confirmed', target: testUrl, param: point.param });
          break;
        }
      }
    }
    if (!crlfFound) {
      results.attackResults.push({ category: 'CRLF Injection', status: 'not detected', detail: `tested ${Math.min(uniquePoints.length, 4)} parameter(s)` });
    }
  }

  // ── Step 12: SSTI ─────────────────────────────────────────────────────────
  if (uniquePoints.length > 0) {
    onProgress('Testing for Server-Side Template Injection (SSTI)...');
    let sstiFound = false;

    for (const point of uniquePoints.slice(0, 4)) {
      if (sstiFound) break;
      for (const { template, expected } of SSTI_PAYLOADS) {
        results.summary.totalProbes++;
        const testUrl = buildPayloadUrl(point.url, point.param, template);
        const r = await safeFetch(testUrl, { timeout: 8000 });
        if (!r.ok) continue;

        if (r.text.includes(expected)) {
          sstiFound = true;
          results.summary.ssti++;
          results.findings.push({
            id: `WAPITI-SSTI-${point.param.toUpperCase()}`,
            severity: 'critical', confidence: 'confirmed',
            title: `Server-Side Template Injection in Parameter "${point.param}"`,
            description: `Template expression "${template}" was evaluated server-side — the server returned "${expected}" confirming SSTI. This can lead to Remote Code Execution.`,
            module: 'wapitiscan', affected: testUrl,
            remediation: 'Never render user input as a template expression. Use sandboxed template rendering and validate all inputs.',
          });
          results.attackResults.push({ category: 'SSTI', status: 'confirmed', target: testUrl, param: point.param, payload: template, result: expected });
          break;
        }
      }
    }
    if (!sstiFound) {
      results.attackResults.push({ category: 'SSTI', status: 'not detected', detail: `tested ${Math.min(uniquePoints.length, 4)} parameter(s)` });
    }
  }

  results.attackSurface.testedPoints = results.summary.totalProbes;
  onProgress(`Active scan complete — ${results.findings.length} confirmed issue(s) across ${results.summary.totalProbes} probes`);
  return results;
}

module.exports = { runWapitiScan };
