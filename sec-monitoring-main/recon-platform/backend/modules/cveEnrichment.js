'use strict';
/**
 * cveEnrichment.js — NVD CVE API v2 Integration (Version-Aware)
 *
 * Queries the NIST National Vulnerability Database (NVD) API v2 using
 * detected technologies from webTechFingerprint / server headers.
 *
 * API: https://services.nvd.nist.gov/rest/json/cves/2.0
 * Free tier: 5 req/30s | With API key: 50 req/30s
 *
 * Set NVD_API_KEY in .env for faster lookups.
 * Attribution: "This product uses data from the NVD API but is not
 * endorsed or certified by the NVD."
 */

const NVD_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const API_KEY  = process.env.NVD_API_KEY || null;

// In-memory cache to avoid repeated API calls during a scan session
const _cache = new Map();

// ── Helpers ───────────────────────────────────────────────────────────────────

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

async function nvdFetch(params) {
  const qs = new URLSearchParams(params).toString();
  const url = `${NVD_BASE}?${qs}`;
  const cacheKey = url;

  if (_cache.has(cacheKey)) return _cache.get(cacheKey);

  const headers = { 'User-Agent': 'ReconScan/2.0 (security-research)' };
  if (API_KEY) headers['apiKey'] = API_KEY;

  try {
    const res = await fetch(url, {
      headers,
      signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) {
      if (res.status === 429 || res.status === 403) {
        // Rate limited — wait and retry once
        await sleep(API_KEY ? 2000 : 6000);
        const retry = await fetch(url, { headers, signal: AbortSignal.timeout(15000) });
        if (!retry.ok) return null;
        const data = await retry.json();
        _cache.set(cacheKey, data);
        return data;
      }
      return null;
    }
    const data = await res.json();
    _cache.set(cacheKey, data);
    return data;
  } catch (_) {
    return null;
  }
}

// Map CVSS v3 base score → severity label
function cvssToSeverity(score) {
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  if (score >= 0.1) return 'low';
  return 'info';
}

// Extract CVSS v3 score from NVD CVE item
function extractScore(cve) {
  const metrics = cve.metrics;
  if (metrics?.cvssMetricV31?.[0]) {
    return {
      score:   metrics.cvssMetricV31[0].cvssData.baseScore,
      vector:  metrics.cvssMetricV31[0].cvssData.vectorString,
      version: '3.1',
    };
  }
  if (metrics?.cvssMetricV30?.[0]) {
    return {
      score:   metrics.cvssMetricV30[0].cvssData.baseScore,
      vector:  metrics.cvssMetricV30[0].cvssData.vectorString,
      version: '3.0',
    };
  }
  if (metrics?.cvssMetricV2?.[0]) {
    return {
      score:   metrics.cvssMetricV2[0].cvssData.baseScore,
      vector:  metrics.cvssMetricV2[0].cvssData.vectorString,
      version: '2.0',
    };
  }
  return { score: 0, vector: '', version: 'N/A' };
}

// ── Simple semver comparison (handles 1.2.3 and 1.2.3.4) ─────────────────────
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

/**
 * Check if a CVE's CPE configuration includes the detected version.
 * Returns true when:
 *  - No CPE nodes exist (can't filter → include conservatively)
 *  - At least one CPE match range covers detectedVersion
 */
function cveAffectsVersion(cve, detectedVersion) {
  if (!detectedVersion) return true; // No version known — include all results

  const configs = cve.configurations || [];
  if (configs.length === 0) return true; // No config data — include conservatively

  for (const config of configs) {
    const nodes = config.nodes || [];
    for (const node of nodes) {
      const matches = node.cpeMatch || [];
      for (const m of matches) {
        if (!m.vulnerable) continue;

        const vStart  = m.versionStartIncluding || m.versionStartExcluding || null;
        const vEnd    = m.versionEndIncluding   || m.versionEndExcluding   || null;
        const startEx = !!m.versionStartExcluding;
        const endEx   = !!m.versionEndExcluding;

        // If no version range is specified, use the CPE version string itself
        if (!vStart && !vEnd) {
          // Extract version from CPE URI: cpe:2.3:a:vendor:product:VERSION:...
          const cpeVer = (m.criteria || '').split(':')[5];
          if (cpeVer && cpeVer !== '*' && cpeVer !== '-') {
            if (cmpVer(detectedVersion, cpeVer) === 0) return true;
          } else {
            return true; // Wildcard CPE — include
          }
          continue;
        }

        // Check start bound
        let startOk = true;
        if (vStart) {
          startOk = startEx
            ? cmpVer(detectedVersion, vStart) > 0
            : cmpVer(detectedVersion, vStart) >= 0;
        }

        // Check end bound
        let endOk = true;
        if (vEnd) {
          endOk = endEx
            ? cmpVer(detectedVersion, vEnd) < 0
            : cmpVer(detectedVersion, vEnd) <= 0;
        }

        if (startOk && endOk) return true;
      }
    }
  }

  return false; // Detected version not in any CPE range
}

// ── Technology → NVD Search Keywords mapping ─────────────────────────────────
// Maps tech name → NVD keyword(s). Ordered most-specific first.
// Technologies that are too generic (java, python) are excluded unless
// a version was detected, so we can form a specific keyword query.

const TECH_KEYWORD_MAP = {
  // Web servers
  'Apache HTTP Server': 'apache http server',
  'Apache':            'apache http server',
  'Nginx':             'nginx',
  'IIS':               'microsoft iis',
  'Lighttpd':          'lighttpd',
  'Caddy':             'caddy server',
  'OpenResty':         'openresty',
  'Tomcat':            'apache tomcat',
  // Languages / Runtimes — only queried when a version is known
  'PHP':               'php',
  'Node.js':           'node.js',
  // Frameworks
  'WordPress':         'wordpress',
  'Drupal':            'drupal',
  'Joomla':            'joomla',
  'Magento':           'magento',
  'Laravel':           'laravel',
  'Django':            'django',
  'Spring':            'spring framework',
  'Struts':            'apache struts',
  'Express.js':        'express.js',
  'Ruby on Rails':     'ruby on rails',
  // CI/CD & Monitoring
  'Jenkins':           'jenkins',
  'Grafana':           'grafana',
  'Kibana':            'kibana',
  'GitLab':            'gitlab',
  'Confluence':        'atlassian confluence',
  'Jira':              'atlassian jira',
  // Infra
  'OpenSSL':           'openssl',
  'JBoss':             'jboss',
  'WebLogic':          'oracle weblogic',
  'Kubernetes':        'kubernetes',
  'Docker':            'docker',
};

// Technologies too generic to query without a version (causes thousands of
// unrelated CVEs). Only queried when version is detected.
const VERSION_REQUIRED = new Set(['php', 'node.js', 'java', 'python', 'ruby', 'mysql', 'postgresql', 'mongodb', 'redis', 'elasticsearch']);

/**
 * Build a list of { keyword, version } query targets from detected technologies.
 * Returns only entries worth querying — i.e. specific products OR generic ones with a known version.
 */
function buildQueryTargets(technologies = [], serverHeader = '', poweredBy = '') {
  const targets = new Map(); // keyword → version (latest version wins)

  for (const tech of technologies) {
    const name    = tech.name || tech;
    const version = tech.version || null;

    for (const [key, kw] of Object.entries(TECH_KEYWORD_MAP)) {
      if (name.toLowerCase().includes(key.toLowerCase())) {
        // Skip generic techs with no version detected
        if (VERSION_REQUIRED.has(kw) && !version) break;

        // Prefer entries with a version
        const existing = targets.get(kw);
        if (!existing || (version && !existing.version)) {
          targets.set(kw, { keyword: kw, version });
        }
        break;
      }
    }
  }

  // Fallback: parse raw server / x-powered-by headers for version strings
  // e.g. "Apache/2.4.51 (Ubuntu)" → keyword: "apache http server", version: "2.4.51"
  const headerPatterns = [
    { re: /Apache\/([\d.]+)/i,         kw: 'apache http server' },
    { re: /nginx\/([\d.]+)/i,          kw: 'nginx' },
    { re: /Microsoft-IIS\/([\d.]+)/i,  kw: 'microsoft iis' },
    { re: /PHP\/([\d.]+)/i,            kw: 'php' },
    { re: /Apache Tomcat\/([\d.]+)/i,  kw: 'apache tomcat' },
    { re: /OpenResty\/([\d.]+)/i,      kw: 'openresty' },
  ];
  const combined = `${serverHeader} ${poweredBy}`;
  for (const { re, kw } of headerPatterns) {
    const m = combined.match(re);
    if (m) {
      const existing = targets.get(kw);
      if (!existing || !existing.version) {
        targets.set(kw, { keyword: kw, version: m[1] });
      }
    }
  }

  return [...targets.values()];
}

// ── Main Export ───────────────────────────────────────────────────────────────

async function runCVEEnrichment(domain, onProgress, context = {}) {
  const results = {
    domain,
    queriedKeywords: [],
    cveFindings:     [],
    findings:        [],
    summary:         { total: 0, critical: 0, high: 0, medium: 0, low: 0, apiReachable: false },
  };

  const {
    technologies = [],
    serverHeader = '',
    poweredBy    = '',
  } = context;

  onProgress('CVE Enrichment: extracting technology keywords...');
  const queryTargets = buildQueryTargets(technologies, serverHeader, poweredBy);
  results.queriedKeywords = queryTargets.map(t => t.version ? `${t.keyword} ${t.version}` : t.keyword);

  if (queryTargets.length === 0) {
    onProgress('CVE Enrichment: no identifiable technologies with sufficient specificity — skipping NVD lookup');
    return results;
  }

  const preview = queryTargets.slice(0, 3).map(t => t.version ? `${t.keyword}@${t.version}` : t.keyword).join(', ');
  onProgress(`CVE Enrichment: querying NVD for ${queryTargets.length} technologies (${preview}${queryTargets.length > 3 ? '...' : ''})`);

  // Limit to first 6 query targets to stay within rate limits
  const limited = queryTargets.slice(0, 6);
  const delaySec = API_KEY ? 0.5 : 6;

  for (let i = 0; i < limited.length; i++) {
    const { keyword, version } = limited[i];
    const searchTerm = version ? `${keyword} ${version}` : keyword;

    if (i > 0) {
      onProgress(`CVE Enrichment: querying NVD for "${searchTerm}" (${i + 1}/${limited.length})...`);
      await sleep(delaySec * 1000);
    }

    try {
      const data = await nvdFetch({
        keywordSearch:   searchTerm,
        resultsPerPage:  version ? 10 : 5,   // More results when version-specific
        startIndex:      0,
        // Sort by CVSS score (NVD API v2 supports cvssV3Severity param)
        ...(version ? {} : {}),
      });

      if (!data) continue;
      results.summary.apiReachable = true;

      const vulnerabilities = data.vulnerabilities || [];
      for (const item of vulnerabilities) {
        const cve = item.cve;
        if (!cve) continue;

        // ── Version filtering ─────────────────────────────────────────────
        // If we detected a specific version, only include CVEs that cover it.
        if (version && !cveAffectsVersion(cve, version)) continue;

        const cveId     = cve.id;
        const published = cve.published?.split('T')[0] || 'Unknown';
        const desc      = cve.descriptions?.find(d => d.lang === 'en')?.value || 'No description available.';
        const scoreInfo = extractScore(cve);
        const severity  = cvssToSeverity(scoreInfo.score);
        const nvdUrl    = `https://nvd.nist.gov/vuln/detail/${cveId}`;

        // Deduplicate by CVE ID
        if (results.cveFindings.some(f => f.cveId === cveId)) continue;

        // Skip info-level CVEs (score 0) — not actionable
        if (scoreInfo.score === 0) continue;

        const versionTag = version ? ` v${version}` : '';
        results.cveFindings.push({
          cveId,
          keyword:     keyword,
          version:     version || null,
          published,
          cvssScore:   scoreInfo.score,
          cvssVersion: scoreInfo.version,
          cvssVector:  scoreInfo.vector,
          severity,
          description: desc,
          nvdUrl,
        });

        results.findings.push({
          id:          `CVE-ENRICH-${cveId}`,
          severity,
          title:       `${cveId} — ${keyword.charAt(0).toUpperCase() + keyword.slice(1)}${versionTag} (CVSS ${scoreInfo.score})`,
          description: `[NVD] ${desc.slice(0, 300)}${desc.length > 300 ? '...' : ''}`,
          module:      'cveEnrichment',
          affected:    nvdUrl,
          remediation: `Review ${nvdUrl} for patches and mitigations. Published: ${published}.`,
          cveId,
          cvssScore:   scoreInfo.score,
        });

        results.summary[severity] = (results.summary[severity] || 0) + 1;
        results.summary.total++;
      }
    } catch (err) {
      onProgress(`CVE Enrichment: error querying NVD for "${searchTerm}": ${err.message}`);
    }
  }

  // Sort findings by CVSS score descending
  results.findings.sort((a, b) => (b.cvssScore || 0) - (a.cvssScore || 0));
  results.cveFindings.sort((a, b) => (b.cvssScore || 0) - (a.cvssScore || 0));

  const reachMsg = results.summary.apiReachable
    ? `CVE Enrichment complete — ${results.summary.total} CVEs found (${results.summary.critical} critical, ${results.summary.high} high)`
    : 'CVE Enrichment: NVD API unreachable (network issue or rate limit)';
  onProgress(reachMsg);

  return results;
}

module.exports = { runCVEEnrichment };
