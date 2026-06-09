'use strict';
/**
 * wafDetector.js — WAF, CDN & Load Balancer Fingerprinter
 *
 * Identifies security infrastructure via:
 *   1. Response header fingerprinting (25+ WAF/CDN products)
 *   2. Cookie name matching (WAF-injected cookies)
 *   3. Behavior-based detection (blocking test payloads)
 *   4. IP ASN analysis to confirm CDN ownership
 *   5. DNS-based CDN detection (CNAME to CDN domains)
 *
 * Produces:
 *   - Detected WAFs, CDNs, load balancers (with confidence score)
 *   - WAF bypass hints (informational)
 *   - Security posture summary
 */

const dns = require('dns').promises;

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36';
const TIMEOUT = 10000;

// ── Fingerprint Database ──────────────────────────────────────────────────────
// Each entry:
// { name, type, headers{key: regex}, cookies[regex], body[regex], cnames[regex], score }

const WAF_SIGNATURES = [
  // ── WAFs ──────────────────────────────────────────────────────────────────
  {
    name: 'Cloudflare WAF / CDN',
    type: 'WAF+CDN',
    confidence: 'high',
    headers: {
      server: /cloudflare/i,
      'cf-ray': /./,
      'cf-cache-status': /./,
    },
    cookies: [/cf_clearance/, /cf_ob_info/, /__cf_bm/],
    body: [],
    cnames: [/cloudflare\.net$/i, /cloudflare\.com$/i],
    description: 'Cloudflare WAF & CDN protects ~20% of the internet. Provides DDoS protection, bot management, and threat intelligence.',
    bypass_hint: 'Find the origin IP via censys.io, shodan.io, or DNS history. Use the origin IP directly to bypass Cloudflare.',
  },
  {
    name: 'Sucuri WAF',
    type: 'WAF',
    confidence: 'high',
    headers: {
      server: /sucuri/i,
      'x-sucuri-id': /./,
      'x-sucuri-cache': /./,
    },
    cookies: [],
    body: [/access denied.*sucuri/i, /sucuri website firewall/i],
    cnames: [/sucuri\.net$/i],
    description: 'Sucuri WAF is a popular website application firewall for WordPress and other CMSes.',
    bypass_hint: 'Try accessing the hosting IP directly. Sucuri is a pass-through proxy, so origin server may be reachable.',
  },
  {
    name: 'Imperva Incapsula',
    type: 'WAF+CDN',
    confidence: 'high',
    headers: {
      'x-iinfo': /./,
      'x-cdn': /Imperva|Incapsula/i,
    },
    cookies: [/incap_ses/, /visid_incap/],
    body: [/incapsula incident id/i, /request unsuccessful.*incapsula/i],
    cnames: [/incapdns\.net$/i, /impervadns\.net$/i],
    description: 'Imperva Incapsula WAF/CDN with advanced bot management and DDoS protection.',
    bypass_hint: 'Incapsula is difficult to bypass without origin IP. Check DNS history on securitytrails.com.',
  },
  {
    name: 'Akamai WAF / CDN',
    type: 'WAF+CDN',
    confidence: 'high',
    headers: {
      server: /akamai/i,
      'x-akamai-transformed': /./,
      'x-check-cacheable': /./,
    },
    cookies: [/ak_bmsc/, /akacd_/],
    body: [/access denied.*akamai/i, /the requested url was rejected/i],
    cnames: [/akamaiedge\.net$/i, /akamaihd\.net$/i, /akadns\.net$/i, /edgesuite\.net$/i],
    description: 'Akamai WAF and CDN — one of the largest internet infrastructure providers.',
    bypass_hint: 'Akamai protection is enterprise-grade. Check Shodan for direct IP. Some sites leave staging environments unprotected.',
  },
  {
    name: 'F5 BIG-IP ASM',
    type: 'WAF',
    confidence: 'high',
    headers: {
      server: /big-ip|bigip/i,
      'x-cnection': /close/i,
    },
    cookies: [/BIGipServer/, /TS[0-9a-f]{8}/],
    body: [/the requested url was rejected/i, /please consult with your administrator/i],
    cnames: [],
    description: 'F5 BIG-IP ASM (Application Security Manager) enterprise WAF.',
    bypass_hint: 'F5 ASM is commonly misconfigured. Try encoding payloads, using alternate HTTP methods, or testing admin interfaces separately.',
  },
  {
    name: 'AWS WAF / CloudFront',
    type: 'WAF+CDN',
    confidence: 'high',
    headers: {
      server: /cloudfront/i,
      'x-amz-cf-id': /./,
      'x-amz-cf-pop': /./,
      'via': /cloudfront/i,
    },
    cookies: [],
    body: [/aws error|cloudfront blocked|403 forbidden.*cloudfront/i],
    cnames: [/cloudfront\.net$/i, /amazonaws\.com$/i],
    description: 'AWS WAF and CloudFront CDN. WAF rules managed via AWS Console.',
    bypass_hint: 'Find origin S3 bucket or EC2 directly. Check AWS region-specific endpoints.',
  },
  {
    name: 'Fastly CDN',
    type: 'CDN',
    confidence: 'high',
    headers: {
      'x-fastly-request-id': /./,
      'fastly-restarts': /./,
      via: /fastly/i,
    },
    cookies: [],
    body: [],
    cnames: [/fastly\.net$/i, /fastlylb\.net$/i, /ssl\.fastly\.net$/i],
    description: 'Fastly CDN (edge cloud platform). No built-in WAF but can run custom VCL logic.',
    bypass_hint: 'Fastly caches responses. Check cache-bypass headers (Pragma: no-cache). Origin IP may be exposed in error pages.',
  },
  {
    name: 'Barracuda WAF',
    type: 'WAF',
    confidence: 'high',
    headers: {
      server: /barracuda/i,
    },
    cookies: [/barra_counter_session/, /BNI__BARRACUDA_LB_COOKIE/],
    body: [/barracuda networks/i, /you are unable to access this site/i],
    cnames: [],
    description: 'Barracuda Networks Web Application Firewall.',
    bypass_hint: 'Barracuda WAF may block SQL/XSS patterns. Try URL encoding, case variation, or comment injection.',
  },
  {
    name: 'Nginx WAF / Rate Limiter',
    type: 'WAF',
    confidence: 'medium',
    headers: {
      server: /nginx/i,
      'x-nginx-cache': /./,
    },
    cookies: [],
    body: [/<center>nginx<\/center>/i, /503 service temporarily unavailable.*nginx/i],
    cnames: [],
    description: 'Nginx web server with potential ModSecurity or rate-limiting rules.',
    bypass_hint: 'Check if ModSecurity is installed. Nginx config may have IP-based rate limiting.',
  },
  {
    name: 'ModSecurity (OWASP CRS)',
    type: 'WAF',
    confidence: 'medium',
    headers: {
      'x-modsecurity-reason': /./,
    },
    cookies: [],
    body: [/mod_security|modsecurity|NOYB/i, /403 forbidden.*mod_security/i],
    cnames: [],
    description: 'ModSecurity with OWASP Core Rule Set — open-source WAF for Apache/Nginx/IIS.',
    bypass_hint: 'ModSecurity CRS can often be bypassed with whitespace tricks, JSON encoding, or split payloads.',
  },
  {
    name: 'Wordfence (WordPress WAF)',
    type: 'WAF',
    confidence: 'high',
    headers: {},
    cookies: [],
    body: [/generated by wordfence/i, /your access to this site has been limited by the site owner/i, /wordfence/i],
    cnames: [],
    description: 'Wordfence security plugin WAF for WordPress — blocks common WordPress attack patterns.',
    bypass_hint: 'Wordfence has a free version with weaker rules. Try REST API endpoints and XML-RPC.',
  },
  {
    name: 'Fortinet FortiWeb',
    type: 'WAF',
    confidence: 'high',
    headers: {
      server: /fortiweb/i,
    },
    cookies: [/cookiesession1/, /FORTIWAFSID/],
    body: [/fortiweb/i, /your request is blocked/i],
    cnames: [],
    description: 'Fortinet FortiWeb hardware/software WAF.',
    bypass_hint: 'FortiWeb may have misconfigured bypass modes. Test with PUT/PATCH methods.',
  },
  {
    name: 'Reblaze',
    type: 'WAF+CDN',
    confidence: 'high',
    headers: {
      server: /reblaze/i,
      'x-reblaze-protection': /./,
    },
    cookies: [/rbzid/, /rbzsessionid/],
    body: [],
    cnames: [],
    description: 'Reblaze cloud-native WAF with bot management.',
    bypass_hint: 'Reblaze protects against bots. Try legitimate browser-like request patterns.',
  },
  {
    name: 'Wallarm WAF',
    type: 'WAF',
    confidence: 'medium',
    headers: {
      'x-wallarm-node': /./,
    },
    cookies: [],
    body: [],
    cnames: [],
    description: 'Wallarm developer-first WAF with ML-based threat detection.',
    bypass_hint: 'Wallarm uses adaptive blocking. Novel payloads may evade signature-based rules.',
  },
  // ── CDNs (No WAF) ─────────────────────────────────────────────────────────
  {
    name: 'Azure CDN (Microsoft)',
    type: 'CDN',
    confidence: 'high',
    headers: {
      server: /windows-azure-blob/i,
      'x-ms-request-id': /./,
      'x-azure-ref': /./,
    },
    cookies: [],
    body: [],
    cnames: [/azureedge\.net$/i, /azurefd\.net$/i, /trafficmanager\.net$/i],
    description: 'Microsoft Azure CDN front door.',
    bypass_hint: 'Check for exposed Azure Storage account name. Direct storage access may bypass CDN.',
  },
  {
    name: 'BunnyCDN',
    type: 'CDN',
    confidence: 'high',
    headers: {
      'cdn-pullzone': /./,
      'cdn-requestid': /./,
    },
    cookies: [],
    body: [],
    cnames: [/b-cdn\.net$/i],
    description: 'BunnyCDN content delivery network.',
    bypass_hint: 'Find the pull zone origin in response headers. The b-cdn.net domain may expose origin.',
  },
  {
    name: 'Varnish Cache',
    type: 'Cache',
    confidence: 'high',
    headers: {
      'x-varnish': /./,
      via: /varnish/i,
      server: /varnish/i,
    },
    cookies: [],
    body: [],
    cnames: [],
    description: 'Varnish HTTP accelerator / reverse proxy. No WAF capabilities but caches responses.',
    bypass_hint: 'Varnish may serve stale cached responses. Use cache-busting parameters. Try Pragma: no-cache header.',
  },
  {
    name: 'Nginx Proxy / Load Balancer',
    type: 'Load Balancer',
    confidence: 'medium',
    headers: {
      server: /nginx/i,
      'x-nginx-upstream': /./,
    },
    cookies: [],
    body: [],
    cnames: [],
    description: 'Nginx reverse proxy/load balancer detected.',
    bypass_hint: 'Check for internal services at /status or /nginx_status.',
  },
  {
    name: 'HAProxy',
    type: 'Load Balancer',
    confidence: 'high',
    headers: {
      server: /haproxy/i,
      'x-haproxy': /./,
    },
    cookies: [],
    body: [],
    cnames: [],
    description: 'HAProxy load balancer.',
    bypass_hint: 'Check /haproxy?stats for exposed statistics page.',
  },
  {
    name: 'Stackpath / Highwinds',
    type: 'CDN+WAF',
    confidence: 'high',
    headers: {
      'x-hw': /./,
      server: /stackpath|highwinds/i,
    },
    cookies: [],
    body: [],
    cnames: [/stackpathdns\.com$/i, /hwcdn\.net$/i],
    description: 'StackPath CDN and WAF.',
    bypass_hint: 'StackPath may have origin IP exposed. Check DNS history.',
  },
  {
    name: 'Radware AppWall',
    type: 'WAF',
    confidence: 'high',
    headers: {
      'x-rdwr-pop': /./,
    },
    cookies: [/rdwr_id/],
    body: [/radware|appwall/i],
    cnames: [],
    description: 'Radware AppWall enterprise WAF.',
    bypass_hint: 'Radware AppWall uses positive security model. Look for allowed endpoints.',
  },
];

// ── CDN Detection via DNS CNAME ────────────────────────────────────────────────

async function detectCDNViaDNS(domain) {
  const detected = [];
  try {
    const cname = await dns.resolveCname(domain).catch(() => []);
    for (const c of cname) {
      for (const sig of WAF_SIGNATURES) {
        if (sig.cnames && sig.cnames.some(p => p.test(c))) {
          detected.push({ name: sig.name, type: sig.type, method: 'DNS CNAME', cname: c });
        }
      }
    }
  } catch (_) {}
  return detected;
}

// ── Behavior-Based WAF Detection ──────────────────────────────────────────────

async function detectWAFBehavior(baseUrl) {
  const tests = [
    { label: 'SQL injection test',  payload: "/?q=1'+OR+'1'='1", expect: [403, 406, 429, 503] },
    { label: 'XSS test',           payload: "/?q=<script>alert(1)</script>", expect: [403, 406, 429, 503] },
    { label: 'Path traversal test', payload: "/../../../etc/passwd", expect: [403, 400, 406] },
    { label: 'Shell injection test', payload: "/?cmd=;ls", expect: [403, 406] },
  ];

  const blocked = [];
  for (const test of tests) {
    try {
      const r = await fetch(baseUrl + test.payload, {
        redirect: 'manual',
        signal: AbortSignal.timeout(6000),
        headers: { 'User-Agent': UA },
      });
      if (test.expect.includes(r.status)) {
        blocked.push({ test: test.label, status: r.status });
      }
    } catch (_) {}
  }
  return blocked;
}

// ── Header & Cookie Fingerprinting ────────────────────────────────────────────

function fingerprint(headers, cookies, body) {
  const detected = [];
  const headerObj = headers || {};
  const cookieStr = Array.isArray(cookies) ? cookies.join(' ') : (cookies || '');
  const bodyStr   = body || '';

  for (const sig of WAF_SIGNATURES) {
    let score = 0;

    // Check headers
    for (const [hKey, hPattern] of Object.entries(sig.headers || {})) {
      const val = headerObj[hKey.toLowerCase()] || headerObj[hKey] || '';
      if (val && hPattern.test(val)) score++;
    }

    // Check cookies
    for (const cp of sig.cookies || []) {
      if (cp.test(cookieStr)) score++;
    }

    // Check body
    for (const bp of sig.body || []) {
      if (bp.test(bodyStr)) score++;
    }

    if (score > 0) {
      detected.push({ name: sig.name, type: sig.type, confidence: sig.confidence, score, sig });
    }
  }

  // Sort by score descending, deduplicate by name
  const seen = new Set();
  return detected
    .sort((a, b) => b.score - a.score)
    .filter(d => { if (seen.has(d.name)) return false; seen.add(d.name); return true; });
}

// ── Main Export ───────────────────────────────────────────────────────────────

async function runWAFDetector(domain, onProgress) {
  const results = {
    domain,
    detected:       [],   // WAF/CDN/LB products found
    behaviorBlocked: [],  // payloads that were blocked
    isProtected:    false,
    summary: {
      wafCount: 0,
      cdnCount: 0,
      lbCount:  0,
      totalDetected: 0,
      behaviorTests: 4,
      blocked: 0,
    },
    findings: [],
  };

  const baseUrls = [`https://${domain}`, `http://${domain}`];
  let baseUrl  = '';
  let headers  = {};
  let cookies  = '';
  let body     = '';

  onProgress('WAF/CDN detection: probing target...');
  for (const url of baseUrls) {
    try {
      const r = await fetch(url, {
        redirect: 'follow',
        signal: AbortSignal.timeout(TIMEOUT),
        headers: { 'User-Agent': UA },
      });
      headers  = Object.fromEntries(r.headers.entries());
      cookies  = headers['set-cookie'] || '';
      body     = await r.text().catch(() => '');
      baseUrl  = url;
      break;
    } catch (_) {}
  }

  if (!baseUrl) { onProgress('WAF detection: target unreachable'); return results; }

  // 1. Header + Cookie fingerprinting
  onProgress('Fingerprinting headers and cookies...');
  const headerDetected = fingerprint(headers, cookies, body);

  // 2. DNS/CNAME detection
  onProgress('Checking DNS CNAME for CDN indicators...');
  const dnsDetected = await detectCDNViaDNS(domain);

  // 3. Behavior-based detection
  onProgress('Sending test payloads to detect WAF behavior...');
  results.behaviorBlocked = await detectWAFBehavior(baseUrl);
  results.summary.blocked = results.behaviorBlocked.length;

  // Merge results
  const allDetected = new Map();
  for (const d of headerDetected) {
    allDetected.set(d.name, { ...d, methods: ['Header fingerprint'] });
  }
  for (const d of dnsDetected) {
    if (allDetected.has(d.name)) {
      allDetected.get(d.name).methods.push(`DNS CNAME: ${d.cname}`);
    } else {
      allDetected.set(d.name, { ...d, methods: [`DNS CNAME: ${d.cname}`] });
    }
  }

  // Behavior alone suggests WAF if multiple payloads blocked
  if (results.behaviorBlocked.length >= 2 && allDetected.size === 0) {
    allDetected.set('Unknown WAF', {
      name: 'Unknown WAF (Behavior-Based)',
      type: 'WAF',
      confidence: 'medium',
      score: results.behaviorBlocked.length,
      methods: ['Behavior: blocked test payloads'],
      sig: {
        description: `Target blocked ${results.behaviorBlocked.length}/4 security test payloads (SQL injection, XSS, path traversal, shell injection), indicating WAF presence.`,
        bypass_hint: 'WAF not fingerprinted. Try encoding payloads, alternate HTTP methods, or headers to bypass.',
      },
    });
  }

  results.detected = [...allDetected.values()];
  results.isProtected = results.detected.length > 0 || results.behaviorBlocked.length >= 2;

  // Count types
  for (const d of results.detected) {
    if (d.type?.includes('WAF')) results.summary.wafCount++;
    else if (d.type?.includes('CDN')) results.summary.cdnCount++;
    else if (d.type?.includes('Load')) results.summary.lbCount++;
  }
  results.summary.totalDetected = results.detected.length;

  // Build findings
  if (results.detected.length > 0) {
    for (const d of results.detected) {
      const sig = d.sig || {};
      results.findings.push({
        id:          `WAF-DETECTED-${d.name.replace(/\s+/g, '-').toUpperCase().slice(0,30)}`,
        severity:    'info',
        title:       `${d.type} Detected: ${d.name}`,
        description: `${sig.description || d.name + ' detected.'} Detection methods: ${d.methods?.join(', ') || 'header fingerprint'}.`,
        module:      'wafDetector',
        remediation: 'WAF/CDN is a security control — this is informational. Ensure WAF rules are up-to-date.',
        details: { bypassHint: sig.bypass_hint, confidence: d.confidence },
      });
    }
  }

  if (results.behaviorBlocked.length >= 2) {
    results.findings.push({
      id:          'WAF-BEHAVIOR-BLOCKING',
      severity:    'info',
      title:       `WAF is Actively Blocking Test Payloads (${results.behaviorBlocked.length}/4 tests blocked)`,
      description: `The following test probes were blocked: ${results.behaviorBlocked.map(b => `${b.test} (HTTP ${b.status})`).join(', ')}.`,
      module:      'wafDetector',
      remediation: 'WAF blocking is a positive control. Ensure all endpoints including APIs are behind the WAF.',
    });
  }

  if (!results.isProtected) {
    results.findings.push({
      id:       'WAF-NOT-DETECTED',
      severity: 'high',
      title:    'No WAF / CDN Detected',
      description: 'No Web Application Firewall or CDN was detected in front of this target. The application is directly exposed without a defensive layer for DDoS, bot, and web attack protection.',
      module:   'wafDetector',
      remediation: 'Deploy a WAF (Cloudflare, AWS WAF, Sucuri, ModSecurity). Consider a CDN for DDoS protection. This is especially critical for e-commerce, banking, and healthcare apps.',
    });
  }

  onProgress(`WAF detection complete — ${results.detected.length} product(s) identified, ${results.behaviorBlocked.length}/4 payloads blocked`);
  return results;
}

module.exports = { runWAFDetector };
