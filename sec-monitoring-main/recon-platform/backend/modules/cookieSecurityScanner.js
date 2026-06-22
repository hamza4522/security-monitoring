'use strict';
/**
 * cookieSecurityScanner.js — Comprehensive Cookie Security Analyzer
 *
 * Inspects all Set-Cookie headers returned from the main domain and
 * derived paths to detect:
 *   1. Missing Secure flag
 *   2. Missing HttpOnly flag
 *   3. Missing / weak SameSite attribute
 *   4. SameSite=None without Secure (blocked by browsers)
 *   5. Missing __Host- / __Secure- prefix where applicable
 *   6. Overly broad Domain attribute (e.g. .example.com)
 *   7. Overly broad Path attribute
 *   8. Long-lived / persistent session cookies (Max-Age / Expires)
 *   9. Sensitive cookie names missing security flags
 *  10. Cookie size (>4096 bytes → risk of being silently dropped)
 *  11. Third-party / cross-site cookies
 *  12. Cookie prefixes (__Host- / __Secure-) validation
 *  13. JWT / base64-encoded tokens in cookies (session data exposure risk)
 *  14. Debug / test cookies left in production
 */

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36';
const PROBE_PATHS = ['/', '/login', '/signin', '/api', '/account', '/auth', '/admin', '/dashboard'];
const PROBE_TIMEOUT = 7000;

// ── Cookie parser ─────────────────────────────────────────────────────────────

/**
 * Parse a single Set-Cookie header string into a structured object.
 */
function parseCookie(raw, source) {
  const parts = raw.split(';').map(p => p.trim());
  const nameValuePart = parts[0] || '';
  const eqIdx = nameValuePart.indexOf('=');
  const name  = eqIdx >= 0 ? nameValuePart.slice(0, eqIdx).trim() : nameValuePart.trim();
  const value = eqIdx >= 0 ? nameValuePart.slice(eqIdx + 1).trim() : '';

  const cookie = {
    name,
    value,
    raw,
    source,
    size: raw.length,
    // Attribute flags
    secure:    false,
    httpOnly:  false,
    sameSite:  null,   // 'Strict' | 'Lax' | 'None' | null
    domain:    null,
    path:      null,
    maxAge:    null,
    expires:   null,
    partitioned: false,
  };

  for (let i = 1; i < parts.length; i++) {
    const part = parts[i];
    const lower = part.toLowerCase();
    if (lower === 'secure')    { cookie.secure   = true; continue; }
    if (lower === 'httponly')  { cookie.httpOnly  = true; continue; }
    if (lower === 'partitioned') { cookie.partitioned = true; continue; }
    if (lower.startsWith('samesite='))  cookie.sameSite = part.split('=')[1]?.trim() || null;
    if (lower.startsWith('domain='))    cookie.domain   = part.split('=')[1]?.trim() || null;
    if (lower.startsWith('path='))      cookie.path     = part.split('=')[1]?.trim() || null;
    if (lower.startsWith('max-age='))   cookie.maxAge   = parseInt(part.split('=')[1] || '0', 10);
    if (lower.startsWith('expires='))   cookie.expires  = part.split('=').slice(1).join('=').trim();
  }

  return cookie;
}

/**
 * Collect Set-Cookie headers from a URL response.
 */
async function collectCookiesFromUrl(url) {
  try {
    const res = await fetch(url, {
      redirect: 'manual',  // Don't follow — inspect the initial response headers
      signal: AbortSignal.timeout(PROBE_TIMEOUT),
      headers: { 'User-Agent': UA, 'Accept': 'text/html,*/*' },
    });
    // res.headers.getSetCookie() is Node 18+; fall back to raw header iteration
    const setCookieHeaders = [];
    res.headers.forEach((val, key) => {
      if (key.toLowerCase() === 'set-cookie') setCookieHeaders.push(val);
    });
    // Also get all cookies from the `set-cookie` header (some Node versions collapse them)
    const rawCombined = res.headers.get('set-cookie');
    if (rawCombined && setCookieHeaders.length === 0) {
      // Rare: multiple set-cookie collapsed — split on newline
      rawCombined.split(/\r?\n/).forEach(h => { if (h.trim()) setCookieHeaders.push(h.trim()); });
    }
    return { headers: Object.fromEntries(res.headers.entries()), setCookieHeaders, status: res.status, url };
  } catch (_) {
    return { headers: {}, setCookieHeaders: [], status: 0, url };
  }
}

// ── Sensitive cookie name patterns ────────────────────────────────────────────

const SENSITIVE_COOKIE_PATTERNS = [
  /session/i, /sess/i, /auth/i, /token/i, /access/i, /jwt/i,
  /userid/i, /user_id/i, /account/i, /login/i, /remember/i,
  /csrf/i, /xsrf/i, /\_rails/i, /phpsessid/i, /jsessionid/i,
  /asp\.net_sessionid/i, /sid/i, /secret/i, /password/i,
];

const DEBUG_COOKIE_PATTERNS = [
  /debug/i, /test/i, /staging/i, /dev_/i, /_dev/i, /localhost/i,
];

// ── JWT / base64 token detection ──────────────────────────────────────────────

function looksLikeJWT(value) {
  // JWT: 3 base64url segments separated by dots
  return /^[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}$/.test(value);
}

function looksLikeBase64Session(value) {
  // Long base64 strings ≥64 chars that decode to JSON (common for Rails/Django sessions)
  if (value.length < 64) return false;
  try {
    const decoded = Buffer.from(value.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    return decoded.startsWith('{') || decoded.startsWith('[');
  } catch (_) {
    return false;
  }
}

// ── Individual cookie finding builder ────────────────────────────────────────

function buildFindings(cookie, domain) {
  const findings = [];
  const isSensitive = SENSITIVE_COOKIE_PATTERNS.some(p => p.test(cookie.name));
  const isDebug     = DEBUG_COOKIE_PATTERNS.some(p => p.test(cookie.name));
  const idSlug     = cookie.name.replace(/[^a-zA-Z0-9]/g, '-').toUpperCase();
  const srcHost    = (() => { try { return new URL(cookie.source).hostname; } catch (_) { return ''; } })();

  // ── 1. Missing Secure flag ────────────────────────────────────────────────
  if (!cookie.secure) {
    findings.push({
      id:          `COOKIE-NO-SECURE-${idSlug}`,
      severity:    isSensitive ? 'high' : 'medium',
      title:       `Cookie "${cookie.name}" Missing Secure Flag`,
      description: `The cookie "${cookie.name}" (set at ${cookie.source}) does not have the Secure attribute. It can be transmitted over unencrypted HTTP connections, allowing interception via man-in-the-middle attacks.`,
      module:      'cookieSecurityScanner',
      affected:    cookie.source,
      remediation: `Add the Secure attribute to this cookie: Set-Cookie: ${cookie.name}=...; Secure. Only serve this cookie over HTTPS.`,
      owasp:       'A02:2021 Cryptographic Failures',
    });
  }

  // ── 2. Missing HttpOnly flag ──────────────────────────────────────────────
  if (!cookie.httpOnly && isSensitive) {
    findings.push({
      id:          `COOKIE-NO-HTTPONLY-${idSlug}`,
      severity:    'medium',
      title:       `Session Cookie "${cookie.name}" Missing HttpOnly Flag`,
      description: `The sensitive cookie "${cookie.name}" does not have the HttpOnly attribute. JavaScript code (including malicious scripts injected via XSS) can read this cookie via document.cookie, leading to session hijacking.`,
      module:      'cookieSecurityScanner',
      affected:    cookie.source,
      remediation: `Add the HttpOnly attribute: Set-Cookie: ${cookie.name}=...; HttpOnly. This prevents JavaScript access to the cookie.`,
      owasp:       'A02:2021 Cryptographic Failures',
    });
  }

  // ── 3. Missing SameSite ───────────────────────────────────────────────────
  if (!cookie.sameSite) {
    findings.push({
      id:          `COOKIE-NO-SAMESITE-${idSlug}`,
      severity:    isSensitive ? 'medium' : 'low',
      title:       `Cookie "${cookie.name}" Missing SameSite Attribute`,
      description: `The cookie "${cookie.name}" has no SameSite attribute. Modern browsers default to "Lax", but older browsers will send this cookie on all cross-site requests, potentially enabling CSRF attacks.`,
      module:      'cookieSecurityScanner',
      affected:    cookie.source,
      remediation: `Set SameSite=Strict for session/authentication cookies, or SameSite=Lax for general cookies. Avoid SameSite=None unless third-party access is explicitly required (and always pair it with Secure).`,
      owasp:       'A01:2021 Broken Access Control',
    });
  }

  // ── 4. SameSite=None without Secure ──────────────────────────────────────
  if (cookie.sameSite?.toLowerCase() === 'none' && !cookie.secure) {
    findings.push({
      id:          `COOKIE-SAMESITE-NONE-NO-SECURE-${idSlug}`,
      severity:    'high',
      title:       `Cookie "${cookie.name}" has SameSite=None Without Secure Flag`,
      description: `The cookie "${cookie.name}" uses SameSite=None but is missing the Secure flag. Browsers (Chrome 80+, Firefox, Safari) will reject this cookie entirely, breaking functionality. Additionally, without Secure it can be sent over HTTP.`,
      module:      'cookieSecurityScanner',
      affected:    cookie.source,
      remediation: `Always pair SameSite=None with the Secure attribute: Set-Cookie: ${cookie.name}=...; SameSite=None; Secure.`,
      owasp:       'A05:2021 Security Misconfiguration',
    });
  }

  // ── 5. SameSite=None (cross-site exposure) ────────────────────────────────
  if (cookie.sameSite?.toLowerCase() === 'none' && cookie.secure) {
    findings.push({
      id:          `COOKIE-SAMESITE-NONE-${idSlug}`,
      severity:    'low',
      title:       `Cookie "${cookie.name}" Sent in Cross-Site Context (SameSite=None)`,
      description: `The cookie "${cookie.name}" is configured with SameSite=None; Secure, meaning it will be sent with all cross-site requests. Unless required for third-party integrations (e.g. payment widgets, OAuth flows), this unnecessarily expands the cookie's attack surface.`,
      module:      'cookieSecurityScanner',
      affected:    cookie.source,
      remediation: 'Restrict to SameSite=Strict or SameSite=Lax unless cross-site access is genuinely required.',
      owasp:       'A01:2021 Broken Access Control',
    });
  }

  // ── 6. Overly broad Domain attribute ─────────────────────────────────────
  if (cookie.domain && cookie.domain.startsWith('.')) {
    const cookieDomain = cookie.domain.replace(/^\./, '');
    if (cookieDomain !== domain && !domain.endsWith(`.${cookieDomain}`)) {
      // Domain doesn't match the scanned domain — likely a misconfiguration
      findings.push({
        id:          `COOKIE-BROAD-DOMAIN-${idSlug}`,
        severity:    'medium',
        title:       `Cookie "${cookie.name}" Has Broad Domain Scope (${cookie.domain})`,
        description: `The cookie "${cookie.name}" sets Domain=${cookie.domain}, which shares the cookie across all subdomains of ${cookieDomain}. If any subdomain is compromised or vulnerable (e.g. an XSS in sub.example.com), the attacker can steal this cookie.`,
        module:      'cookieSecurityScanner',
        affected:    cookie.source,
        remediation: `Omit the Domain attribute or set it as precisely as possible. Avoid the leading dot unless subdomain sharing is explicitly required.`,
        owasp:       'A01:2021 Broken Access Control',
      });
    }
  }

  // ── 7. Very long-lived persistent cookie ─────────────────────────────────
  const maxAgeSeconds = cookie.maxAge;
  const thirtyDays    = 30 * 24 * 3600;
  const oneYear       = 365 * 24 * 3600;
  if (maxAgeSeconds !== null && maxAgeSeconds > oneYear && isSensitive) {
    findings.push({
      id:          `COOKIE-LONG-LIVED-${idSlug}`,
      severity:    'medium',
      title:       `Sensitive Cookie "${cookie.name}" Has Excessive Lifetime (${Math.round(maxAgeSeconds / 86400)} days)`,
      description: `The authentication/session cookie "${cookie.name}" persists for ${Math.round(maxAgeSeconds / 86400)} days. Long-lived session tokens greatly extend the attack window if the token is stolen.`,
      module:      'cookieSecurityScanner',
      affected:    cookie.source,
      remediation: 'Keep session cookie lifetime short (≤24h for sensitive cookies). Use refresh tokens for long-lived sessions. Consider rotating session IDs on privilege escalation.',
      owasp:       'A02:2021 Cryptographic Failures',
    });
  }

  // ── 8. Cookie size > 4096 bytes ──────────────────────────────────────────
  if (cookie.size > 4096) {
    findings.push({
      id:          `COOKIE-TOO-LARGE-${idSlug}`,
      severity:    'low',
      title:       `Cookie "${cookie.name}" Exceeds 4KB Limit (${cookie.size} bytes)`,
      description: `The cookie "${cookie.name}" is ${cookie.size} bytes, exceeding the 4096-byte browser limit. Browsers may silently drop this cookie, causing authentication failures. Large cookies also increase request overhead.`,
      module:      'cookieSecurityScanner',
      affected:    cookie.source,
      remediation: 'Store session data server-side and use only a short session ID in the cookie. Avoid storing large objects in cookies.',
      owasp:       'A05:2021 Security Misconfiguration',
    });
  }

  // ── 9. Missing __Host- / __Secure- cookie prefix ─────────────────────────
  if (isSensitive && cookie.secure && !cookie.name.startsWith('__Host-') && !cookie.name.startsWith('__Secure-')) {
    findings.push({
      id:          `COOKIE-NO-PREFIX-${idSlug}`,
      severity:    'info',
      title:       `Sensitive Cookie "${cookie.name}" Could Use __Host- or __Secure- Prefix`,
      description: `The cookie "${cookie.name}" handles authentication but does not use the __Host- or __Secure- prefix convention. Cookie prefixes are enforced by browsers and prevent subdomain override attacks and cookie injection.`,
      module:      'cookieSecurityScanner',
      affected:    cookie.source,
      remediation: 'Rename session cookies to use __Host- prefix (requires Secure + Path=/ + no Domain attribute) for the strongest protection, or __Secure- prefix (requires Secure flag).',
      owasp:       'A02:2021 Cryptographic Failures',
    });
  }

  // ── 10. __Host- prefix without required attributes ────────────────────────
  if (cookie.name.startsWith('__Host-')) {
    const violations = [];
    if (!cookie.secure)              violations.push('missing Secure flag');
    if (cookie.path !== '/')         violations.push(`Path must be "/" (got "${cookie.path || '/'}")`);
    if (cookie.domain)               violations.push(`Domain attribute must NOT be set (got "${cookie.domain}")`);
    if (violations.length > 0) {
      findings.push({
        id:          `COOKIE-HOST-PREFIX-INVALID-${idSlug}`,
        severity:    'high',
        title:       `Cookie "${cookie.name}" Violates __Host- Prefix Requirements`,
        description: `The __Host- prefixed cookie "${cookie.name}" fails browser validation: ${violations.join('; ')}. The browser will reject this cookie, breaking functionality.`,
        module:      'cookieSecurityScanner',
        affected:    cookie.source,
        remediation: '__Host- cookies must have: Secure flag, Path=/, and no Domain attribute.',
        owasp:       'A05:2021 Security Misconfiguration',
      });
    }
  }

  // ── 11. __Secure- prefix without Secure ──────────────────────────────────
  if (cookie.name.startsWith('__Secure-') && !cookie.secure) {
    findings.push({
      id:          `COOKIE-SECURE-PREFIX-INVALID-${idSlug}`,
      severity:    'high',
      title:       `Cookie "${cookie.name}" Violates __Secure- Prefix Requirements`,
      description: `The __Secure- prefixed cookie "${cookie.name}" is missing the Secure attribute. Browsers will reject this cookie entirely.`,
      module:      'cookieSecurityScanner',
      affected:    cookie.source,
      remediation: 'Add the Secure flag to all cookies with the __Secure- prefix.',
      owasp:       'A05:2021 Security Misconfiguration',
    });
  }

  // ── 12. JWT value in cookie ───────────────────────────────────────────────
  if (looksLikeJWT(cookie.value)) {
    findings.push({
      id:          `COOKIE-JWT-VALUE-${idSlug}`,
      severity:    cookie.httpOnly ? 'low' : 'medium',
      title:       `Cookie "${cookie.name}" Contains a JWT Token`,
      description: `The cookie "${cookie.name}" appears to contain a JWT. JWTs are base64-encoded and contain claims visible to anyone who intercepts the cookie. ${!cookie.httpOnly ? 'Without HttpOnly, JavaScript can read the JWT.' : ''} Ensure the JWT is signed and verify it on every request.`,
      module:      'cookieSecurityScanner',
      affected:    cookie.source,
      remediation: 'Use HttpOnly + Secure + SameSite=Strict on JWT cookies. Never store sensitive data in JWT payload without encryption. Validate signature on every request.',
      owasp:       'A02:2021 Cryptographic Failures',
    });
  }

  // ── 13. Base64 session data ───────────────────────────────────────────────
  if (!looksLikeJWT(cookie.value) && looksLikeBase64Session(cookie.value)) {
    findings.push({
      id:          `COOKIE-B64-SESSION-${idSlug}`,
      severity:    'medium',
      title:       `Cookie "${cookie.name}" Appears to Contain Encoded Session Data`,
      description: `The cookie "${cookie.name}" value decodes to what appears to be a JSON object, suggesting the full session object is stored client-side. This may expose sensitive data and is tamper-able if not signed/encrypted.`,
      module:      'cookieSecurityScanner',
      affected:    cookie.source,
      remediation: 'Store session data server-side and reference it with a short opaque session ID. If client-side storage is required, sign and encrypt the payload.',
      owasp:       'A02:2021 Cryptographic Failures',
    });
  }

  // ── 14. Debug / test cookie in production ────────────────────────────────
  if (isDebug) {
    findings.push({
      id:          `COOKIE-DEBUG-${idSlug}`,
      severity:    'medium',
      title:       `Debug/Test Cookie "${cookie.name}" Found in Production`,
      description: `The cookie "${cookie.name}" has a name suggesting it was set for debugging or testing purposes. This may indicate development configuration is active in production.`,
      module:      'cookieSecurityScanner',
      affected:    cookie.source,
      remediation: 'Remove all debug/test cookies from production deployments. Audit cookie-setting code for environment-specific logic.',
      owasp:       'A05:2021 Security Misconfiguration',
    });
  }

  return findings;
}

// ── Main export ───────────────────────────────────────────────────────────────

async function runCookieSecurityScanner(domain, onProgress) {
  const results = {
    domain,
    cookies:  [],
    findings: [],
    summary: {
      totalCookies:      0,
      missingSecure:     0,
      missingHttpOnly:   0,
      missingSameSite:   0,
      jwtCookies:        0,
      longLived:         0,
      debugCookies:      0,
      probedPaths:       0,
    },
  };

  const seenCookieKeys = new Set(); // deduplicate by name+source

  const baseUrls = [`https://${domain}`, `http://${domain}`];

  // Determine which base URL actually works
  let workingBase = null;
  onProgress('Cookie Security: probing target reachability...');
  for (const base of baseUrls) {
    try {
      const r = await fetch(base, { signal: AbortSignal.timeout(5000), redirect: 'follow', headers: { 'User-Agent': UA } });
      if (r.status > 0) { workingBase = base; break; }
    } catch (_) {}
  }

  if (!workingBase) {
    onProgress('Cookie Security: target unreachable — skipping');
    return results;
  }

  // Probe multiple paths to collect cookies from login pages, API, etc.
  const urlsToProbe = PROBE_PATHS.map(p => workingBase + p);
  onProgress(`Cookie Security: collecting Set-Cookie headers from ${urlsToProbe.length} paths...`);

  const probeResults = await Promise.allSettled(urlsToProbe.map(url => collectCookiesFromUrl(url)));

  results.summary.probedPaths = urlsToProbe.length;

  for (const pr of probeResults) {
    if (pr.status !== 'fulfilled') continue;
    const { setCookieHeaders, url } = pr.value;

    for (const rawCookie of setCookieHeaders) {
      if (!rawCookie || !rawCookie.trim()) continue;
      const cookie = parseCookie(rawCookie, url);
      if (!cookie.name) continue;

      const key = `${cookie.name}@${url}`;
      if (seenCookieKeys.has(key)) continue;
      seenCookieKeys.add(key);

      results.cookies.push(cookie);
    }
  }

  results.summary.totalCookies = results.cookies.length;

  if (results.cookies.length === 0) {
    onProgress('Cookie Security: no Set-Cookie headers found');
    return results;
  }

  onProgress(`Cookie Security: analyzing ${results.cookies.length} cookie(s)...`);

  // Analyze each cookie
  const allFindings = [];
  const seenFindingIds = new Set();

  for (const cookie of results.cookies) {
    const cookieFindings = buildFindings(cookie, domain);
    for (const f of cookieFindings) {
      if (!seenFindingIds.has(f.id)) {
        seenFindingIds.add(f.id);
        allFindings.push(f);
      }
    }

    // Update summary counters
    if (!cookie.secure)                          results.summary.missingSecure++;
    if (!cookie.httpOnly && SENSITIVE_COOKIE_PATTERNS.some(p => p.test(cookie.name))) results.summary.missingHttpOnly++;
    if (!cookie.sameSite)                        results.summary.missingSameSite++;
    if (looksLikeJWT(cookie.value))              results.summary.jwtCookies++;
    if (cookie.maxAge !== null && cookie.maxAge > 365 * 24 * 3600) results.summary.longLived++;
    if (DEBUG_COOKIE_PATTERNS.some(p => p.test(cookie.name))) results.summary.debugCookies++;
  }

  results.findings = allFindings;

  onProgress(
    `Cookie Security: scan complete — ${results.cookies.length} cookie(s), ${allFindings.length} issue(s) found`
  );

  return results;
}

module.exports = { runCookieSecurityScanner };
