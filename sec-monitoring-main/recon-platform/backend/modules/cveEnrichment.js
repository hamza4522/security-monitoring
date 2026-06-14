'use strict';
/**
 * cveEnrichment.js — NVD CVE API v2 Integration
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
  // Try CVSS v3.1 then v3.0 then v2
  const metrics = cve.metrics;
  if (metrics?.cvssMetricV31?.[0]) {
    return {
      score: metrics.cvssMetricV31[0].cvssData.baseScore,
      vector: metrics.cvssMetricV31[0].cvssData.vectorString,
      version: '3.1',
    };
  }
  if (metrics?.cvssMetricV30?.[0]) {
    return {
      score: metrics.cvssMetricV30[0].cvssData.baseScore,
      vector: metrics.cvssMetricV30[0].cvssData.vectorString,
      version: '3.0',
    };
  }
  if (metrics?.cvssMetricV2?.[0]) {
    return {
      score: metrics.cvssMetricV2[0].cvssData.baseScore,
      vector: metrics.cvssMetricV2[0].cvssData.vectorString,
      version: '2.0',
    };
  }
  return { score: 0, vector: '', version: 'N/A' };
}

// ── Technology → Search Keywords mapping ─────────────────────────────────────

const TECH_KEYWORD_MAP = {
  // Web servers
  'Apache HTTP Server': 'apache http server',
  'Apache':            'apache http server',
  'Nginx':             'nginx',
  'IIS':               'microsoft iis',
  'Lighttpd':          'lighttpd',
  'Caddy':             'caddy server',
  // Languages / Runtimes
  'PHP':               'php',
  'Node.js':           'node.js',
  'Python':            'python',
  'Ruby':              'ruby',
  'Java':              'java',
  // Frameworks
  'WordPress':         'wordpress',
  'Drupal':            'drupal',
  'Joomla':            'joomla',
  'Magento':           'magento',
  'Laravel':           'laravel',
  'Django':            'django',
  'Spring':            'spring framework',
  'Struts':            'apache struts',
  'Express':           'express.js',
  // Databases
  'MySQL':             'mysql',
  'PostgreSQL':        'postgresql',
  'MongoDB':           'mongodb',
  'Redis':             'redis',
  'Elasticsearch':     'elasticsearch',
  // CI/CD & Monitoring
  'Jenkins':           'jenkins',
  'Grafana':           'grafana',
  'Kibana':            'kibana',
  'GitLab':            'gitlab',
  'Confluence':        'atlassian confluence',
  'Jira':              'atlassian jira',
  // Infra
  'OpenSSL':           'openssl',
  'Tomcat':            'apache tomcat',
  'JBoss':             'jboss',
  'WebLogic':          'oracle weblogic',
  'Kubernetes':        'kubernetes',
  'Docker':            'docker',
};

// Extract keywords from detected technologies + server header
function extractKeywords(technologies = [], serverHeader = '', poweredBy = '') {
  const keywords = new Set();

  // Map detected tech names
  for (const tech of technologies) {
    const name = tech.name || tech;
    for (const [key, kw] of Object.entries(TECH_KEYWORD_MAP)) {
      if (name.toLowerCase().includes(key.toLowerCase())) {
        keywords.add(kw);
        break;
      }
    }
  }

  // Fallback: parse raw server header
  const combined = `${serverHeader} ${poweredBy}`.toLowerCase();
  for (const [key, kw] of Object.entries(TECH_KEYWORD_MAP)) {
    if (combined.includes(key.toLowerCase())) keywords.add(kw);
  }

  return [...keywords];
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
  const keywords = extractKeywords(technologies, serverHeader, poweredBy);
  results.queriedKeywords = keywords;

  if (keywords.length === 0) {
    onProgress('CVE Enrichment: no identifiable technologies — skipping NVD lookup');
    return results;
  }

  onProgress(`CVE Enrichment: querying NVD for ${keywords.length} technologies (${keywords.slice(0, 3).join(', ')}${keywords.length > 3 ? '...' : ''})`);

  // Limit to first 6 keywords to avoid too many API calls
  const queryKeywords = keywords.slice(0, 6);
  const delaySec = API_KEY ? 0.5 : 6; // Rate-limit safe delays

  for (let i = 0; i < queryKeywords.length; i++) {
    const kw = queryKeywords[i];

    if (i > 0) {
      onProgress(`CVE Enrichment: querying NVD for "${kw}" (${i + 1}/${queryKeywords.length})...`);
      await sleep(delaySec * 1000);
    }

    try {
      const data = await nvdFetch({
        keywordSearch: kw,
        resultsPerPage: 5,  // Top 5 most recently published CVEs per technology
        startIndex: 0,
      });

      if (!data) continue;
      results.summary.apiReachable = true;

      const vulnerabilities = data.vulnerabilities || [];
      for (const item of vulnerabilities) {
        const cve = item.cve;
        if (!cve) continue;

        const cveId      = cve.id;
        const published  = cve.published?.split('T')[0] || 'Unknown';
        const desc       = cve.descriptions?.find(d => d.lang === 'en')?.value || 'No description available.';
        const scoreInfo  = extractScore(cve);
        const severity   = cvssToSeverity(scoreInfo.score);
        const nvdUrl     = `https://nvd.nist.gov/vuln/detail/${cveId}`;

        // Deduplicate by CVE ID
        if (results.cveFindings.some(f => f.cveId === cveId)) continue;

        results.cveFindings.push({
          cveId,
          keyword: kw,
          published,
          cvssScore: scoreInfo.score,
          cvssVersion: scoreInfo.version,
          cvssVector: scoreInfo.vector,
          severity,
          description: desc,
          nvdUrl,
        });

        results.findings.push({
          id:          `CVE-ENRICH-${cveId}`,
          severity,
          title:       `${cveId} — ${kw.charAt(0).toUpperCase() + kw.slice(1)} (CVSS ${scoreInfo.score})`,
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
      onProgress(`CVE Enrichment: error querying NVD for "${kw}": ${err.message}`);
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
