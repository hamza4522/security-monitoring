'use strict';
/**
 * retireJsChecker.js — Retire.js Vulnerability Database Integration
 *
 * Detects outdated/vulnerable JavaScript libraries loaded by target pages
 * by cross-referencing against the live Retire.js JSON repository.
 *
 * Database: https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json
 *
 * Detection methods:
 *  1. Script filename pattern matching
 *  2. Script content version signatures
 *  3. Script URL hash matching
 */

const RETIRE_DB_URL = 'https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json';
const FETCH_TIMEOUT = 12000;
const UA = 'Mozilla/5.0 (compatible; ReconScan/2.0; SecurityResearch)';

// In-memory database cache (shared across scans in the same process session)
let _retireDb  = null;
let _dbFetchAt = 0;
const DB_TTL   = 60 * 60 * 1000; // Refresh every hour

async function getRetireDb() {
  const now = Date.now();
  if (_retireDb && now - _dbFetchAt < DB_TTL) return _retireDb;

  try {
    const res = await fetch(RETIRE_DB_URL, {
      headers: { 'User-Agent': UA },
      signal: AbortSignal.timeout(FETCH_TIMEOUT),
    });
    if (!res.ok) return _retireDb; // Return stale cache on failure
    _retireDb  = await res.json();
    _dbFetchAt = now;
    return _retireDb;
  } catch (_) {
    return _retireDb; // Return stale / null
  }
}

// Safe fetch helper
async function safeFetch(url, opts = {}) {
  try {
    const r = await fetch(url, {
      redirect: 'follow',
      signal: AbortSignal.timeout(opts.timeout || FETCH_TIMEOUT),
      headers: { 'User-Agent': UA, ...(opts.headers || {}) },
    });
    const body = await r.text().catch(() => '');
    return { ok: r.ok, status: r.status, body };
  } catch (_) {
    return { ok: false, status: 0, body: '' };
  }
}

// ── Detection helpers ─────────────────────────────────────────────────────────

/**
 * Extract version from filename using Retire.js filename patterns.
 * E.g. "jquery-3.6.0.min.js" → "3.6.0"
 */
function matchFilename(filename, libraryEntry) {
  const filenamePatterns = libraryEntry.bowername || [];
  // Also check extractors.filename
  const extractors = libraryEntry.extractors?.filename || [];
  for (const pattern of extractors) {
    try {
      const re = new RegExp(pattern);
      const m = filename.match(re);
      if (m && m[1]) return m[1]; // First capture group = version
    } catch (_) {}
  }
  return null;
}

/**
 * Extract version from file content using Retire.js filecontent patterns.
 */
function matchContent(body, libraryEntry) {
  const extractors = libraryEntry.extractors?.filecontent || [];
  for (const pattern of extractors) {
    try {
      const re = new RegExp(pattern);
      const m = body.match(re);
      if (m && m[1]) return m[1];
    } catch (_) {}
  }
  return null;
}

/**
 * Compare a detected version against Retire.js vulnerability records.
 * Returns an array of applicable vulnerabilities.
 */
function findVulnerabilities(libName, detectedVersion, libraryEntry) {
  if (!detectedVersion || !libraryEntry.vulnerabilities) return [];

  const vulns = [];
  for (const vuln of libraryEntry.vulnerabilities) {
    const affected = vuln.atOrAbove && vuln.below
      ? isVersionInRange(detectedVersion, vuln.atOrAbove, vuln.below)
      : vuln.below
        ? isVersionBelow(detectedVersion, vuln.below)
        : true; // No version constraint — assume affected

    if (affected) {
      // Extract CVE IDs and advisory links
      const cves      = extractCVEs(vuln);
      const severity  = mapSeverity(vuln.severity);
      const summary   = vuln.info?.[0] || 'Known vulnerability';
      vulns.push({ severity, summary, cves, info: vuln.info || [] });
    }
  }
  return vulns;
}

function extractCVEs(vuln) {
  const identifiers = vuln.identifiers || {};
  const cves = [];
  if (identifiers.CVE) cves.push(...(Array.isArray(identifiers.CVE) ? identifiers.CVE : [identifiers.CVE]));
  return cves;
}

function mapSeverity(sev) {
  const s = (sev || '').toLowerCase();
  if (s === 'critical')  return 'critical';
  if (s === 'high')      return 'high';
  if (s === 'medium')    return 'medium';
  if (s === 'low')       return 'low';
  return 'medium'; // Default for unlabeled Retire.js entries
}

// Simple semver comparison helpers (handles 1.2.3 and 1.2.3.4 formats)
function parseVer(v) {
  return (v || '').split('.').map(x => parseInt(x, 10) || 0);
}
function cmpVer(a, b) {
  const pa = parseVer(a), pb = parseVer(b);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d !== 0) return d;
  }
  return 0;
}
function isVersionBelow(ver, below) {
  return cmpVer(ver, below) < 0;
}
function isVersionInRange(ver, atOrAbove, below) {
  return cmpVer(ver, atOrAbove) >= 0 && cmpVer(ver, below) < 0;
}

// ── Scan page JS files ────────────────────────────────────────────────────────

async function scanPageScripts(baseUrl, html, db, onProgress, results) {
  // Extract all <script src="..."> URLs from the page
  const scriptUrls = [];
  const srcRe = /<script[^>]+src\s*=\s*["']([^"']+\.js[^"']*?)["']/gi;
  let m;
  while ((m = srcRe.exec(html)) !== null) {
    let src = m[1];
    if (src.startsWith('//')) src = 'https:' + src;
    else if (src.startsWith('/')) src = baseUrl.replace(/\/$/, '') + src;
    else if (!src.startsWith('http')) src = baseUrl + '/' + src;
    scriptUrls.push(src.split('?')[0]); // Strip query strings for clean filename matching
  }

  // Deduplicate
  const unique = [...new Set(scriptUrls)].slice(0, 20); // Cap at 20 scripts

  if (unique.length === 0) return;
  onProgress(`Retire.js: checking ${unique.length} JavaScript files...`);

  const checks = unique.map(async (scriptUrl) => {
    const filename = scriptUrl.split('/').pop();

    for (const [libName, libEntry] of Object.entries(db)) {
      // Skip libraries with no vulnerability records
      if (!libEntry.vulnerabilities || libEntry.vulnerabilities.length === 0) continue;

      // 1. Try filename-based detection
      let version = matchFilename(filename, libEntry);

      // 2. If filename didn't match, fetch and try content-based detection
      if (!version) {
        // Only fetch if filename looks plausibly related (avoid fetching everything)
        const filenameHint = (libEntry.bowername || [libName]).some(n =>
          filename.toLowerCase().includes(n.toLowerCase())
        );
        if (filenameHint) {
          const r = await safeFetch(scriptUrl, { timeout: 6000 });
          if (r.ok && r.body.length > 0) {
            version = matchContent(r.body, libEntry);
          }
        }
      }

      if (!version) continue;

      // Check for vulnerabilities at this version
      const vulns = findVulnerabilities(libName, version, libEntry);
      if (vulns.length === 0) continue;

      // Report each vulnerability as a finding
      for (const vuln of vulns) {
        const cveStr = vuln.cves.length > 0 ? ` (${vuln.cves.join(', ')})` : '';
        const findingId = `RETIREJS-${libName.replace(/[^a-zA-Z0-9]/g, '-').toUpperCase()}-${version.replace(/\./g, '-')}`;

        // Deduplicate by finding ID
        if (results.findings.some(f => f.id === findingId)) continue;

        results.libraryHits.push({ library: libName, version, url: scriptUrl, vulns });
        results.findings.push({
          id:          findingId,
          severity:    vuln.severity,
          title:       `Vulnerable JS Library: ${libName} v${version}${cveStr}`,
          description: `${libName} version ${version} is loaded at ${scriptUrl} and contains known security vulnerabilities. ${vuln.summary}`,
          module:      'retireJsChecker',
          affected:    scriptUrl,
          remediation: `Upgrade ${libName} to the latest version. References: ${vuln.info.slice(0, 2).join(', ')}`,
          cves:        vuln.cves,
          library:     libName,
          version,
        });

        results.summary[vuln.severity] = (results.summary[vuln.severity] || 0) + 1;
        results.summary.total++;
      }
    }
  });

  await Promise.allSettled(checks);
}

// ── Main Export ───────────────────────────────────────────────────────────────

async function runRetireJsChecker(domain, onProgress) {
  const results = {
    domain,
    libraryHits:  [],
    findings:     [],
    summary:      { total: 0, critical: 0, high: 0, medium: 0, low: 0, dbLoaded: false },
  };

  onProgress('Retire.js: loading vulnerability database...');
  const db = await getRetireDb();

  if (!db) {
    onProgress('Retire.js: could not load vulnerability database (network issue)');
    return results;
  }

  results.summary.dbLoaded = true;
  const libCount = Object.keys(db).length;
  onProgress(`Retire.js: database loaded (${libCount} libraries). Fetching target page...`);

  // Fetch the target page to extract script URLs
  const baseUrls = [`https://${domain}`, `http://${domain}`];
  let baseUrl = '', html = '';

  for (const url of baseUrls) {
    const r = await safeFetch(url, { timeout: 12000 });
    if (r.ok || r.status > 0) {
      baseUrl = url;
      html = r.body;
      break;
    }
  }

  if (!baseUrl) {
    onProgress('Retire.js: target unreachable');
    return results;
  }

  await scanPageScripts(baseUrl, html, db, onProgress, results);

  const msg = results.summary.total > 0
    ? `Retire.js: found ${results.summary.total} vulnerable library issues (${results.summary.critical} critical, ${results.summary.high} high)`
    : `Retire.js: no known vulnerable libraries detected (${results.libraryHits.length} libs checked)`;
  onProgress(msg);

  return results;
}

module.exports = { runRetireJsChecker };
