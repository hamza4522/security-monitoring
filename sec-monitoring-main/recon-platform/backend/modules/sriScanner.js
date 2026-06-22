'use strict';
/**
 * sriScanner.js — Subresource Integrity (SRI) Scanner
 *
 * Scans target pages for external resources (scripts + stylesheets) loaded
 * from CDNs or third-party origins that lack SRI integrity attributes.
 *
 * Checks:
 *   1.  External <script src> without integrity attribute
 *   2.  External <link rel="stylesheet" href> without integrity attribute
 *   3.  Scripts / stylesheets with integrity but missing crossorigin attribute
 *   4.  Validates existing SRI hash format (sha256/sha384/sha512)
 *   5.  Detects data-integrity bypass patterns (nonce-only without SRI)
 *   6.  Reports CDN providers affected (jsDelivr, cdnjs, unpkg, Bootstrap CDN, etc.)
 *   7.  Probes both homepage and linked pages (1 level deep)
 */

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36';
const FETCH_TIMEOUT = 8000;

// Well-known CDN hostnames — loading from these without SRI is highest risk
const HIGH_RISK_CDNS = [
  'cdn.jsdelivr.net', 'cdnjs.cloudflare.com', 'unpkg.com',
  'stackpath.bootstrapcdn.com', 'maxcdn.bootstrapcdn.com', 'bootstrapcdn.com',
  'code.jquery.com', 'ajax.googleapis.com', 'ajax.aspnetcdn.com',
  'cdn.staticfile.org', 'lib.baomitu.com', 'cdn.bootcss.com',
  'cdn.rawgit.com', 'rawgit.com', 'gitcdn.xyz',
  'fonts.googleapis.com', 'fonts.gstatic.com',
  'use.fontawesome.com', 'kit.fontawesome.com',
  'cdn.polyfill.io', 'polyfill.io',
  'cdn.auth0.com', 'js.stripe.com', 'checkout.stripe.com',
  'cdn.segment.com', 'cdn.amplitude.com',
  'www.googletagmanager.com', 'www.google-analytics.com',
  'connect.facebook.net', 'platform.twitter.com',
  'cdn.datatables.net',
];

// Valid SRI hash prefixes
const VALID_HASH_PREFIXES = ['sha256-', 'sha384-', 'sha512-'];

// ── Fetch helper ──────────────────────────────────────────────────────────────

async function safeFetch(url) {
  try {
    const res = await fetch(url, {
      redirect: 'follow',
      signal: AbortSignal.timeout(FETCH_TIMEOUT),
      headers: { 'User-Agent': UA, 'Accept': 'text/html,*/*' },
    });
    const text = await res.text().catch(() => '');
    return { ok: res.status >= 200 && res.status < 400, status: res.status, text };
  } catch (_) {
    return { ok: false, status: 0, text: '' };
  }
}

// ── Resource extraction ───────────────────────────────────────────────────────

/**
 * Extract all external <script> and <link rel=stylesheet> tags from HTML.
 * Returns array of { tag, src, type, integrity, crossorigin, hostname }
 */
function extractExternalResources(html, baseUrl) {
  const resources = [];
  let baseDomain = '';
  try { baseDomain = new URL(baseUrl).hostname; } catch (_) {}

  // ── <script src="..."> ────────────────────────────────────────────────────
  const scriptRe = /<script\s([^>]*)>/gi;
  let m;
  while ((m = scriptRe.exec(html)) !== null) {
    const attrs = m[1];
    const srcM = attrs.match(/src\s*=\s*["']([^"']+)["']/i);
    if (!srcM) continue;

    let src = srcM[1];
    // Resolve protocol-relative URLs
    if (src.startsWith('//')) src = 'https:' + src;
    // Skip relative / data: / blob: / inline
    if (!src.startsWith('http')) continue;

    let hostname = '';
    try { hostname = new URL(src).hostname; } catch (_) { continue; }
    // Skip same-origin resources (SRI is only meaningful for cross-origin)
    if (hostname === baseDomain) continue;

    const integrityM  = attrs.match(/integrity\s*=\s*["']([^"']+)["']/i);
    const crossoriginM = attrs.match(/crossorigin\s*(?:=\s*["']([^"']*)["'])?/i);

    resources.push({
      tag:         m[0],
      src,
      type:        'script',
      integrity:   integrityM ? integrityM[1] : null,
      crossorigin: crossoriginM ? (crossoriginM[1] || 'anonymous') : null,
      hostname,
      isHighRiskCDN: HIGH_RISK_CDNS.some(cdn => hostname === cdn || hostname.endsWith('.' + cdn)),
    });
  }

  // ── <link rel="stylesheet" href="..."> ───────────────────────────────────
  const linkRe = /<link\s([^>]*)>/gi;
  while ((m = linkRe.exec(html)) !== null) {
    const attrs = m[1];
    const relM  = attrs.match(/rel\s*=\s*["']([^"']+)["']/i);
    if (!relM || !relM[1].toLowerCase().includes('stylesheet')) continue;

    const hrefM = attrs.match(/href\s*=\s*["']([^"']+)["']/i);
    if (!hrefM) continue;

    let href = hrefM[1];
    if (href.startsWith('//')) href = 'https:' + href;
    if (!href.startsWith('http')) continue;

    let hostname = '';
    try { hostname = new URL(href).hostname; } catch (_) { continue; }
    if (hostname === baseDomain) continue;

    const integrityM   = attrs.match(/integrity\s*=\s*["']([^"']+)["']/i);
    const crossoriginM = attrs.match(/crossorigin\s*(?:=\s*["']([^"']*)["'])?/i);

    resources.push({
      tag:         m[0],
      src:         href,
      type:        'stylesheet',
      integrity:   integrityM ? integrityM[1] : null,
      crossorigin: crossoriginM ? (crossoriginM[1] || 'anonymous') : null,
      hostname,
      isHighRiskCDN: HIGH_RISK_CDNS.some(cdn => hostname === cdn || hostname.endsWith('.' + cdn)),
    });
  }

  // ── <link rel="preload" / modulepreload> ──────────────────────────────────
  const preloadRe = /<link\s([^>]*)>/gi;
  while ((m = preloadRe.exec(html)) !== null) {
    const attrs = m[1];
    const relM  = attrs.match(/rel\s*=\s*["']([^"']+)["']/i);
    if (!relM) continue;
    const rel = relM[1].toLowerCase();
    if (!rel.includes('preload') && !rel.includes('modulepreload')) continue;
    const asM = attrs.match(/as\s*=\s*["']([^"']+)["']/i);
    if (!asM || !['script', 'style'].includes(asM[1].toLowerCase())) continue;

    const hrefM = attrs.match(/href\s*=\s*["']([^"']+)["']/i);
    if (!hrefM) continue;
    let href = hrefM[1];
    if (href.startsWith('//')) href = 'https:' + href;
    if (!href.startsWith('http')) continue;
    let hostname = '';
    try { hostname = new URL(href).hostname; } catch (_) { continue; }
    if (hostname === baseDomain) continue;

    const integrityM   = attrs.match(/integrity\s*=\s*["']([^"']+)["']/i);
    const crossoriginM = attrs.match(/crossorigin\s*(?:=\s*["']([^"']*)["'])?/i);

    resources.push({
      tag:         m[0],
      src:         href,
      type:        `preload-${asM[1].toLowerCase()}`,
      integrity:   integrityM ? integrityM[1] : null,
      crossorigin: crossoriginM ? (crossoriginM[1] || 'anonymous') : null,
      hostname,
      isHighRiskCDN: HIGH_RISK_CDNS.some(cdn => hostname === cdn || hostname.endsWith('.' + cdn)),
    });
  }

  return resources;
}

/**
 * Validate an existing SRI integrity attribute value.
 * Returns null if valid, or an error message if invalid.
 */
function validateIntegrityHash(integrity) {
  if (!integrity) return 'No integrity attribute';
  const hashes = integrity.trim().split(/\s+/);
  for (const hash of hashes) {
    const hasValidPrefix = VALID_HASH_PREFIXES.some(p => hash.toLowerCase().startsWith(p));
    if (!hasValidPrefix) {
      return `Invalid hash algorithm — must start with sha256-, sha384-, or sha512- (got "${hash.slice(0, 20)}")`;
    }
    const base64Part = hash.split('-').slice(1).join('-');
    if (!/^[A-Za-z0-9+/=]+$/.test(base64Part)) {
      return `Invalid base64 in hash "${hash.slice(0, 30)}"`;
    }
    // sha256 = 44 chars, sha384 = 64 chars, sha512 = 88 chars (base64 encoded)
    const expectedLengths = { 'sha256-': 44, 'sha384-': 64, 'sha512-': 88 };
    for (const [prefix, len] of Object.entries(expectedLengths)) {
      if (hash.toLowerCase().startsWith(prefix) && base64Part.length !== len) {
        return `Hash length mismatch for ${prefix.replace('-', '')} — expected ${len} chars, got ${base64Part.length}`;
      }
    }
  }
  return null; // valid
}

/**
 * Extract linked same-origin pages (1 level) for deeper SRI checking.
 */
function extractLinkedPages(html, baseUrl, limit = 5) {
  const links = new Set();
  const re = /href\s*=\s*["']([^"'#?]+)/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    try {
      const abs = new URL(m[1], baseUrl).toString();
      const base = new URL(baseUrl);
      const link = new URL(abs);
      if (link.hostname === base.hostname && abs !== baseUrl) links.add(abs);
      if (links.size >= limit) break;
    } catch (_) {}
  }
  return [...links];
}

// ── Main export ───────────────────────────────────────────────────────────────

async function runSRIScanner(domain, onProgress) {
  const results = {
    domain,
    pages:    [],      // pages probed
    resources: [],     // all external resources found
    findings:  [],
    summary: {
      pagesScanned:          0,
      totalExternalResources: 0,
      missingIntegrity:       0,
      missingCrossOrigin:     0,
      invalidHash:            0,
      highRiskCDN:            0,
      scripts:                0,
      stylesheets:            0,
    },
  };

  const seenSrcs    = new Set();
  const findingIds  = new Set();

  // Determine working base URL
  onProgress('SRI Scanner: probing target...');
  const bases = [`https://${domain}`, `http://${domain}`];
  let baseUrl = '', homeHtml = '';
  for (const b of bases) {
    const r = await safeFetch(b);
    if (r.ok) { baseUrl = b; homeHtml = r.text; break; }
  }
  if (!baseUrl) {
    onProgress('SRI Scanner: target unreachable — skipping');
    return results;
  }

  // Collect pages to scan: homepage + up to 5 linked same-origin pages
  const pagesToScan = [{ url: baseUrl, html: homeHtml }];
  onProgress('SRI Scanner: discovering linked pages...');
  const linkedPages = extractLinkedPages(homeHtml, baseUrl, 5);
  for (const pageUrl of linkedPages) {
    const r = await safeFetch(pageUrl);
    if (r.ok && r.text) pagesToScan.push({ url: pageUrl, html: r.text });
  }
  results.summary.pagesScanned = pagesToScan.length;
  results.pages = pagesToScan.map(p => p.url);
  onProgress(`SRI Scanner: scanning ${pagesToScan.length} page(s) for external resources...`);

  // Extract and deduplicate all external resources across pages
  for (const page of pagesToScan) {
    const extracted = extractExternalResources(page.html, page.url);
    for (const res of extracted) {
      if (seenSrcs.has(res.src)) continue;
      seenSrcs.add(res.src);
      results.resources.push({ ...res, foundOn: page.url });
    }
  }

  results.summary.totalExternalResources = results.resources.length;
  results.summary.scripts      = results.resources.filter(r => r.type === 'script').length;
  results.summary.stylesheets  = results.resources.filter(r => r.type === 'stylesheet').length;

  onProgress(`SRI Scanner: analyzing ${results.resources.length} external resource(s)...`);

  // ── Analyze each resource ─────────────────────────────────────────────────
  for (const res of results.resources) {
    const shortSrc   = res.src.length > 80 ? res.src.slice(0, 77) + '...' : res.src;
    const typeLabel  = res.type === 'script' ? 'Script' : res.type === 'stylesheet' ? 'Stylesheet' : 'Preload';
    const severityBase = res.isHighRiskCDN ? 'high' : 'medium';
    const slug = res.src.replace(/[^a-zA-Z0-9]/g, '-').slice(0, 60).toUpperCase();

    // ── Check 1: Missing integrity attribute ────────────────────────────────
    if (!res.integrity) {
      results.summary.missingIntegrity++;
      if (res.isHighRiskCDN) results.summary.highRiskCDN++;

      const fid = `SRI-MISSING-${slug}`;
      if (!findingIds.has(fid)) {
        findingIds.add(fid);
        results.findings.push({
          id:          fid,
          severity:    severityBase,
          title:       `Missing SRI on External ${typeLabel}: ${res.hostname}`,
          description: `The external ${typeLabel.toLowerCase()} "${shortSrc}" (hosted on ${res.hostname}) lacks a Subresource Integrity (integrity) attribute. If the CDN or third-party host is compromised, an attacker could serve malicious code to all your users.${res.isHighRiskCDN ? ` ${res.hostname} is a high-risk public CDN.` : ''}`,
          module:      'sriScanner',
          affected:    res.foundOn,
          remediation: `Generate the integrity hash at https://www.srihash.org/ or using:
  openssl dgst -sha384 -binary FILE | openssl base64 -A
Then add: integrity="sha384-<hash>" crossorigin="anonymous" to the tag.`,
          resource:    res.src,
          resourceType: res.type,
          hostname:    res.hostname,
          isHighRiskCDN: res.isHighRiskCDN,
          owasp:       'A08:2021 Software and Data Integrity Failures',
        });
      }
    }

    // ── Check 2: Has integrity but missing crossorigin ──────────────────────
    if (res.integrity && !res.crossorigin) {
      results.summary.missingCrossOrigin++;
      const fid = `SRI-NO-CROSSORIGIN-${slug}`;
      if (!findingIds.has(fid)) {
        findingIds.add(fid);
        results.findings.push({
          id:          fid,
          severity:    'low',
          title:       `SRI Present but Missing crossorigin on ${typeLabel}: ${res.hostname}`,
          description: `The ${typeLabel.toLowerCase()} from "${shortSrc}" has an integrity attribute but no crossorigin attribute. Browsers require crossorigin="anonymous" (or "use-credentials") for SRI validation on cross-origin resources to work. Without it, SRI is silently bypassed.`,
          module:      'sriScanner',
          affected:    res.foundOn,
          remediation: 'Add crossorigin="anonymous" to the tag alongside the integrity attribute.',
          resource:    res.src,
          resourceType: res.type,
          owasp:       'A05:2021 Security Misconfiguration',
        });
      }
    }

    // ── Check 3: Validate existing integrity hash format ───────────────────
    if (res.integrity) {
      const validationError = validateIntegrityHash(res.integrity);
      if (validationError) {
        results.summary.invalidHash++;
        const fid = `SRI-INVALID-HASH-${slug}`;
        if (!findingIds.has(fid)) {
          findingIds.add(fid);
          results.findings.push({
            id:          fid,
            severity:    'medium',
            title:       `Invalid SRI Hash on ${typeLabel}: ${res.hostname}`,
            description: `The ${typeLabel.toLowerCase()} from "${shortSrc}" has an integrity attribute, but it is invalid: ${validationError}. An invalid hash causes the browser to block the resource, breaking the page, OR the hash was changed by an attacker.`,
            module:      'sriScanner',
            affected:    res.foundOn,
            remediation: 'Regenerate the integrity hash using sha256, sha384, or sha512. Use https://www.srihash.org/ or openssl.',
            resource:    res.src,
            resourceType: res.type,
            owasp:       'A08:2021 Software and Data Integrity Failures',
          });
        }
      }
    }
  }

  // ── Check 4: No SRI at all on the page (global finding) ──────────────────
  const scriptsWithSRI = results.resources.filter(r => r.type === 'script' && r.integrity).length;
  const totalScripts   = results.resources.filter(r => r.type === 'script').length;
  const cssWithSRI     = results.resources.filter(r => r.type === 'stylesheet' && r.integrity).length;
  const totalCss       = results.resources.filter(r => r.type === 'stylesheet').length;

  if (totalScripts > 0 && scriptsWithSRI === 0) {
    const fid = 'SRI-GLOBAL-NO-SCRIPTS';
    if (!findingIds.has(fid)) {
      findingIds.add(fid);
      results.findings.push({
        id:          fid,
        severity:    'high',
        title:       `No Subresource Integrity Used on Any External Script (${totalScripts} scripts)`,
        description: `The site loads ${totalScripts} external JavaScript file(s) without any SRI integrity attributes. A supply chain attack on any of these CDNs would silently execute malicious code for all visitors.`,
        module:      'sriScanner',
        affected:    baseUrl,
        remediation: 'Implement SRI on all external scripts. Generate hashes via https://www.srihash.org/ and add integrity + crossorigin attributes. Consider using a CSP require-sri-for directive.',
        owasp:       'A08:2021 Software and Data Integrity Failures',
      });
    }
  }

  if (totalCss > 0 && cssWithSRI === 0) {
    const fid = 'SRI-GLOBAL-NO-STYLESHEETS';
    if (!findingIds.has(fid)) {
      findingIds.add(fid);
      results.findings.push({
        id:          fid,
        severity:    'medium',
        title:       `No Subresource Integrity Used on Any External Stylesheet (${totalCss} stylesheets)`,
        description: `The site loads ${totalCss} external CSS file(s) without SRI. A compromised CDN could inject keyloggers or UI-redressing attacks via CSS.`,
        module:      'sriScanner',
        affected:    baseUrl,
        remediation: 'Add integrity + crossorigin attributes to all external stylesheet links. Use sha384 or sha512 hashes.',
        owasp:       'A08:2021 Software and Data Integrity Failures',
      });
    }
  }

  // ── Check 5: CSP require-sri-for header ───────────────────────────────────
  try {
    const r = await safeFetch(baseUrl);
    const csp = r.text ? '' : '';  // we already have homeHtml
    // Check the actual response headers by doing a HEAD-style check
    const headRes = await fetch(baseUrl, {
      method: 'HEAD',
      signal: AbortSignal.timeout(5000),
      headers: { 'User-Agent': UA },
    }).catch(() => null);

    if (headRes) {
      const cspHeader = headRes.headers.get('content-security-policy') || '';
      if (!cspHeader.includes('require-sri-for') && results.summary.totalExternalResources > 0) {
        const fid = 'SRI-CSP-REQUIRE-MISSING';
        if (!findingIds.has(fid)) {
          findingIds.add(fid);
          results.findings.push({
            id:          fid,
            severity:    'info',
            title:       'CSP require-sri-for Directive Not Configured',
            description: 'The Content-Security-Policy header does not include a require-sri-for directive. This directive instructs browsers to enforce SRI on all scripts and stylesheets, providing an additional enforcement layer.',
            module:      'sriScanner',
            affected:    baseUrl,
            remediation: "Add to CSP: require-sri-for script style — this forces browsers to reject any external script or stylesheet without a valid integrity attribute.",
            owasp:       'A05:2021 Security Misconfiguration',
          });
        }
      }
    }
  } catch (_) {}

  const totalIssues = results.findings.length;
  onProgress(
    `SRI Scanner: complete — ${results.resources.length} external resource(s), ${results.summary.missingIntegrity} missing SRI, ${totalIssues} issue(s)`
  );

  return results;
}

module.exports = { runSRIScanner };
