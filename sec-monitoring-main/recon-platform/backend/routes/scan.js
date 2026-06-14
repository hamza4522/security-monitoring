const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { runWhoisLookup }       = require('../modules/whoisLookup');
const { runAssetDiscovery }    = require('../modules/assetDiscovery');
const { runDNSAssessment }     = require('../modules/dnsAssessment');
const { runPortScan }          = require('../modules/portScan');
const { runServiceFingerprint }= require('../modules/serviceFingerprint');
const { runWebTechFingerprint }= require('../modules/webTechFingerprint');
const { runVulnAssessment }    = require('../modules/vulnAssessment');
const { runWapitiScan }        = require('../modules/wapitiscan');
const { runCMSVulnScan }       = require('../modules/cmsVulnScan');
const { runSSLScan }           = require('../modules/sslScan');
const { runNucleiChecks }      = require('../modules/nucleiChecks');
const { runJSSecretScanner }   = require('../modules/jsSecretScanner');
const { runSubdomainTakeover } = require('../modules/subdomainTakeover');
const { runWAFDetector }       = require('../modules/wafDetector');
const { runCVEEnrichment }     = require('../modules/cveEnrichment');
const { runRetireJsChecker }   = require('../modules/retireJsChecker');
const { runAPIDiscovery }      = require('../modules/apiDiscovery');
const { calculateRiskScore }   = require('../utils/riskScoring');

module.exports = (scans, broadcast, alertEngine = null) => {
  const router = express.Router();

  // Start a new scan
  router.post('/start', async (req, res) => {
    const { domain, modules = ['all'] } = req.body;

    if (!domain) {
      return res.status(400).json({ error: 'Domain is required' });
    }

    // Sanitize: strip protocol, port, path, query string, fragment
    // Accepts: https://example.com, example.com:8080/path, www.example.com/page?q=1 etc.
    let cleanDomain = domain.trim();
    if (/^https?:\/\//i.test(cleanDomain)) {
      try { cleanDomain = new URL(cleanDomain).hostname; } catch (_) {
        cleanDomain = cleanDomain.replace(/^https?:\/\//i, '');
      }
    }
    cleanDomain = cleanDomain.replace(/[/:?#].*$/, '').toLowerCase().trim();

    // Basic domain validation (after cleaning)
    const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    if (!domainRegex.test(cleanDomain)) {
      return res.status(400).json({ error: 'Invalid domain format. Please enter a domain like: example.com' });
    }

    // Use the cleaned domain from here on
    const domain_ = cleanDomain;

    const scanId = uuidv4();
    const scan = {
      id: scanId,
      domain: domain_,
      status: 'running',
      progress: 0,
      startedAt: new Date().toISOString(),
      completedAt: null,
      modules: {
        whoisLookup:        { status: 'pending', data: null },
        assetDiscovery:     { status: 'pending', data: null },
        sslScan:            { status: 'pending', data: null },
        dnsAssessment:      { status: 'pending', data: null },
        portScan:           { status: 'pending', data: null },
        serviceFingerprint: { status: 'pending', data: null },
        webTechFingerprint: { status: 'pending', data: null },
        wafDetector:        { status: 'pending', data: null },
        vulnAssessment:     { status: 'pending', data: null },
        nucleiChecks:       { status: 'pending', data: null },
        jsSecretScanner:    { status: 'pending', data: null },
        subdomainTakeover:  { status: 'pending', data: null },
        wapitiscan:         { status: 'pending', data: null },
        cmsVulnScan:        { status: 'pending', data: null },
        cveEnrichment:      { status: 'pending', data: null },
        retireJsChecker:    { status: 'pending', data: null },
        apiDiscovery:       { status: 'pending', data: null },
      },
      findings: [],
      riskScore: null,
      summary: null,
    };

    scans.set(scanId, scan);
    res.json({ scanId, status: 'started' });

    // Run modules asynchronously
    runScanPipeline(scanId, domain_, scan, scans, broadcast, alertEngine);
  });

  // Compare two completed scans — GET /api/scan/compare?a=id1&b=id2
  router.get('/compare', (req, res) => {
    const { a, b } = req.query;
    if (!a || !b) return res.status(400).json({ error: 'Query params a and b (scan IDs) are required' });
    const scanA = scans.get(a);
    const scanB = scans.get(b);
    if (!scanA) return res.status(404).json({ error: `Scan A (${a}) not found` });
    if (!scanB) return res.status(404).json({ error: `Scan B (${b}) not found` });

    const idsA = new Set((scanA.findings || []).map(f => f.id));
    const idsB = new Set((scanB.findings || []).map(f => f.id));

    const newFindings      = (scanB.findings || []).filter(f => !idsA.has(f.id));
    const resolvedFindings = (scanA.findings || []).filter(f => !idsB.has(f.id));
    const sharedFindings   = (scanA.findings || []).filter(f => idsB.has(f.id));
    const scoreChange      = (scanB.riskScore?.score || 0) - (scanA.riskScore?.score || 0);

    res.json({
      scanA: { id: scanA.id, domain: scanA.domain, startedAt: scanA.startedAt, riskScore: scanA.riskScore, findingCount: scanA.findings?.length || 0 },
      scanB: { id: scanB.id, domain: scanB.domain, startedAt: scanB.startedAt, riskScore: scanB.riskScore, findingCount: scanB.findings?.length || 0 },
      scoreChange,
      newFindings,
      resolvedFindings,
      sharedFindings,
      summary: { newCount: newFindings.length, resolvedCount: resolvedFindings.length, sharedCount: sharedFindings.length, improved: scoreChange < 0 },
    });
  });

  // Get scan status and results
  router.get('/:scanId', (req, res) => {
    const scan = scans.get(req.params.scanId);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    res.json(scan);
  });

  // List all scans
  router.get('/', (req, res) => {
    const list = Array.from(scans.values()).map(s => ({
      id: s.id,
      domain: s.domain,
      status: s.status,
      progress: s.progress,
      startedAt: s.startedAt,
      completedAt: s.completedAt,
      riskScore: s.riskScore,
    }));
    res.json(list.sort((a, b) => new Date(b.startedAt) - new Date(a.startedAt)));
  });

  // Cancel a scan
  router.delete('/:scanId', (req, res) => {
    const scan = scans.get(req.params.scanId);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    scan.status = 'cancelled';
    scans.set(req.params.scanId, scan);
    res.json({ status: 'cancelled' });
  });

  return router;
};

/**
 * Wraps a promise with a timeout. If the promise doesn't resolve within
 * the given timeMs, it rejects with a timeout error.
 */
function withTimeout(promise, timeMs, label) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`${label} timed out after ${Math.round(timeMs / 1000)}s`));
    }, timeMs);
    promise.then(
      (val) => { clearTimeout(timer); resolve(val); },
      (err) => { clearTimeout(timer); reject(err); }
    );
  });
}

const MODULE_TIMEOUT = 120000; // 2 minutes per module
const GLOBAL_TIMEOUT = 600000; // 10 minutes for the entire scan

async function runScanPipeline(scanId, domain, scan, scans, broadcast, alertEngine) {
  const emit = (event, data) => {
    broadcast(scanId, { event, ...data });
  };

  const updateModule = (moduleName, status, data = null) => {
    scan.modules[moduleName] = { status, data };
    scans.set(scanId, scan);
  };

  const moduleList = [
    { key: 'whoisLookup',       label: 'WHOIS & IP Intel',         runner: runWhoisLookup,         weight: 9 },
    { key: 'assetDiscovery',    label: 'Asset Discovery',          runner: runAssetDiscovery,      weight: 10 },
    // SSL scan runs after asset discovery so it can reuse the discovered subdomains
    {
      key: 'sslScan',
      label: 'SSL/TLS Certificate Scan',
      weight: 10,
      runner: (domain, onProgress) => {
        // Pull subdomains discovered by the assetDiscovery module at runtime
        const subdomains = scan.modules.assetDiscovery?.data?.subdomains || [];
        return runSSLScan(domain, onProgress, subdomains);
      },
    },
    { key: 'dnsAssessment',     label: 'DNS Assessment',           runner: runDNSAssessment,        weight: 10 },
    { key: 'portScan',          label: 'Port Scanning',            runner: runPortScan,             weight: 11 },
    { key: 'serviceFingerprint',label: 'Service Fingerprinting',   runner: runServiceFingerprint,   weight: 11 },
    { key: 'webTechFingerprint',label: 'Web Tech Fingerprinting',  runner: runWebTechFingerprint,   weight: 10 },
    {
      key: 'wafDetector',
      label: 'WAF / CDN Detection',
      weight: 8,
      runner: (domain, onProgress) => runWAFDetector(domain, onProgress),
    },
    { key: 'vulnAssessment',    label: 'Vulnerability Assessment', runner: runVulnAssessment,       weight: 10 },
    { key: 'nucleiChecks',      label: 'Nuclei-style Checks',      runner: runNucleiChecks,         weight: 10 },
    { key: 'jsSecretScanner',   label: 'JavaScript Secret Scanner',runner: runJSSecretScanner,      weight: 9 },
    {
      key: 'subdomainTakeover',
      label: 'Subdomain Takeover Check',
      weight: 9,
      runner: (domain, onProgress) => {
        const subdomains = scan.modules.assetDiscovery?.data?.subdomains || [];
        return runSubdomainTakeover(domain, onProgress, subdomains);
      },
    },
    { key: 'wapitiscan',        label: 'Active Web Attacks',       runner: runWapitiScan,           weight: 10 },
    { key: 'cmsVulnScan',       label: 'CMS Vulnerability Scan',  runner: runCMSVulnScan,          weight: 9 },
    {
      // CVE Enrichment: runs after webTechFingerprint to pass detected tech context
      key: 'cveEnrichment',
      label: 'NVD CVE Enrichment',
      weight: 8,
      runner: (domain, onProgress) => {
        // Gather context from previously completed modules
        const webTechData = scan.modules.webTechFingerprint?.data;
        // Handle multiTarget structure (take first — the primary domain result)
        const primaryWebTech = webTechData?.multiTarget
          ? webTechData.targetResults?.find(r => r?.domain === domain) || webTechData.targetResults?.[0]
          : webTechData;
        const technologies = primaryWebTech?.technologies || [];
        // Extract server / x-powered-by from the detected response headers for version-aware queries
        const serverHeader  = primaryWebTech?._responseHeaders?.server || '';
        const poweredBy     = primaryWebTech?._responseHeaders?.['x-powered-by'] || '';
        return runCVEEnrichment(domain, onProgress, { technologies, serverHeader, poweredBy });
      },
    },
    {
      // Retire.js: scan target JS files against the vulnerability database
      key: 'retireJsChecker',
      label: 'Retire.js Library Check',
      weight: 7,
      runner: runRetireJsChecker,
    },
    {
      // API Discovery: enumerate public API endpoints via 9 detection techniques
      key: 'apiDiscovery',
      label: 'Public API Discovery',
      weight: 9,
      runner: runAPIDiscovery,
    },
  ];

  // Global scan timeout — ensures scan ALWAYS finishes
  const globalTimer = setTimeout(() => {
    if (scan.status === 'running') {
      console.error(`[SCAN ${scanId}] Global timeout reached (${GLOBAL_TIMEOUT / 1000}s). Forcing completion.`);
      scan.riskScore = calculateRiskScore(scan);
      scan.summary = buildSummary(scan);
      scan.status = 'complete';
      scan.completedAt = new Date().toISOString();
      scans.set(scanId, scan);
      emit('scan_complete', { riskScore: scan.riskScore, summary: scan.summary, timedOut: true });
    }
  }, GLOBAL_TIMEOUT);

  let completedWeight = 0;

  try {
    for (const mod of moduleList) {
      if (scan.status === 'cancelled' || scan.status === 'complete') break;

      emit('module_start', { module: mod.key, label: mod.label });
      updateModule(mod.key, 'running');

      try {
        let result;
        const multiTargetModules = new Set([
          'dnsAssessment', 'portScan', 'serviceFingerprint', 'webTechFingerprint',
          'wafDetector', 'vulnAssessment', 'nucleiChecks', 'jsSecretScanner',
          'wapitiscan', 'cmsVulnScan', 'retireJsChecker',
          // cveEnrichment runs only for the primary domain (context-dependent)
        ]);

        if (multiTargetModules.has(mod.key)) {
          const subdomains = scan.modules.assetDiscovery?.data?.subdomains || [];
          const targets = [...new Set([domain, ...subdomains])];
          
          const tasks = targets.map(target => async () => {
            if (scan.status === 'cancelled' || scan.status === 'complete') return null;
            try {
              return await withTimeout(
                mod.runner(target, (msg) => {
                  emit('module_progress', { module: mod.key, message: `[${target}] ${msg}` });
                }),
                MODULE_TIMEOUT,
                `${mod.label} on ${target}`
              );
            } catch (err) {
              console.error(`[SCAN ${scanId}] ${mod.label} on ${target} error: ${err.message}`);
              emit('module_progress', { module: mod.key, message: `Error on ${target}: ${err.message}` });
              return null;
            }
          });
          
          const targetResults = await runConcurrent(tasks, 3); // 3 concurrent targets
          const validResults = targetResults.filter(r => r !== null);
          
          if (validResults.length > 0) {
            result = { multiTarget: true, targetResults: validResults };
          } else {
            result = null;
          }
        } else {
          result = await withTimeout(
            mod.runner(domain, (msg) => {
              emit('module_progress', { module: mod.key, message: msg });
            }),
            MODULE_TIMEOUT,
            mod.label
          );
        }

        updateModule(mod.key, 'complete', result);
        completedWeight += mod.weight;
        scan.progress = completedWeight;

        // Collect findings
        if (result) {
          if (result.multiTarget && result.targetResults) {
            result.targetResults.forEach(tr => {
              if (tr && tr.findings) scan.findings.push(...tr.findings);
            });
          } else if (result.findings) {
            scan.findings.push(...result.findings);
          }
        }

        emit('module_complete', { module: mod.key, label: mod.label, progress: scan.progress });
      } catch (err) {
        console.error(`[SCAN ${scanId}] Module ${mod.key} error: ${err.message}`);
        updateModule(mod.key, 'error', { error: err.message });
        completedWeight += mod.weight;
        scan.progress = completedWeight;
        emit('module_error', { module: mod.key, label: mod.label, error: err.message });
        // Continue to next module — don't stall the pipeline
      }
    }

    // Final risk scoring and summary
    if (scan.status !== 'cancelled' && scan.status !== 'complete') {
      scan.riskScore = calculateRiskScore(scan);
      scan.summary = buildSummary(scan);
      scan.status = 'complete';
      scan.completedAt = new Date().toISOString();
      scans.set(scanId, scan);
      emit('scan_complete', { riskScore: scan.riskScore, summary: scan.summary });
      // Fire alert rules
      if (alertEngine) { try { alertEngine.evaluateAndFire(scan); } catch(e) { console.error('[Alerts] Error:', e.message); } }
    }
  } finally {
    clearTimeout(globalTimer);
  }
}

function mergeResults(resultsList, mainDomain) {
  if (!resultsList || resultsList.length === 0) return null;
  const merged = JSON.parse(JSON.stringify(resultsList[0]));
  merged.domain = mainDomain;

  for (let i = 1; i < resultsList.length; i++) {
    const current = resultsList[i];
    for (const key of Object.keys(current)) {
      if (key === 'domain') continue;

      if (Array.isArray(current[key])) {
        merged[key] = (merged[key] || []).concat(current[key]);
      } else if (typeof current[key] === 'object' && current[key] !== null) {
        if (!merged[key]) merged[key] = {};
        for (const subKey of Object.keys(current[key])) {
          if (typeof current[key][subKey] === 'number') {
            merged[key][subKey] = (merged[key][subKey] || 0) + current[key][subKey];
          } else if (Array.isArray(current[key][subKey])) {
            merged[key][subKey] = (merged[key][subKey] || []).concat(current[key][subKey]);
          } else if (merged[key][subKey] === undefined) {
            merged[key][subKey] = current[key][subKey];
          }
        }
      } else if (typeof current[key] === 'number') {
        merged[key] = (merged[key] || 0) + current[key];
      }
    }
  }

  // Deduplicate findings
  if (merged.findings && Array.isArray(merged.findings)) {
    const seen = new Set();
    merged.findings = merged.findings.filter(f => {
      const key = `${f.id}-${f.affected || f.title}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  return merged;
}

async function runConcurrent(tasks, limit) {
  const results = [];
  const executing = [];
  for (const task of tasks) {
    const p = task().then(r => {
      executing.splice(executing.indexOf(p), 1);
      return r;
    });
    executing.push(p);
    results.push(p);
    if (executing.length >= limit) {
      await Promise.race(executing);
    }
  }
  return Promise.all(results);
}

function buildSummary(scan) {
  const { modules } = scan;
  const whois  = modules.whoisLookup?.data;
  const assets = modules.assetDiscovery?.data;
  const ssl    = modules.sslScan?.data;
  const dns    = modules.dnsAssessment?.data;
  const ports  = modules.portScan?.data;
  const services = modules.serviceFingerprint?.data;
  const web    = modules.webTechFingerprint?.data;
  const vuln   = modules.vulnAssessment?.data;
  const wapiti = modules.wapitiscan?.data;
  const cms    = modules.cmsVulnScan?.data;

  return {
    totalAssets:          assets?.subdomains?.length || 0,
    liveHosts:            assets?.liveHosts?.length || 0,
    openPorts:            ports?.openPorts?.length || 0,
    exposedServices:      services?.services?.length || 0,
    criticalFindings:     scan.findings.filter(f => f.severity === 'critical').length,
    highFindings:         scan.findings.filter(f => f.severity === 'high').length,
    mediumFindings:       scan.findings.filter(f => f.severity === 'medium').length,
    lowFindings:          scan.findings.filter(f => f.severity === 'low').length,
    technologies:         web?.technologies?.length || 0,
    dnsIssues:            dns?.issues?.length || 0,
    vulnChecks:           vuln?.checks?.length || 0,
    vulnPassed:           vuln?.summary?.pass || 0,
    vulnFailed:           vuln?.summary?.fail || 0,
    activeProbes:         wapiti?.attackSurface?.testedPoints || 0,
    activeAttackFindings: wapiti?.findings?.length || 0,
    xssFound:             wapiti?.summary?.xss || 0,
    sqliFound:            wapiti?.summary?.sqli || 0,
    cmdiFound:            wapiti?.summary?.cmdi || 0,
    detectedPlatforms:    cms?.detectedPlatforms?.map(p => p.name) || [],
    cmsFindings:          cms?.findings?.length || 0,
    // WHOIS
    registrar:            whois?.registrar || null,
    daysUntilExpiry:      whois?.daysUntilExpiry ?? null,
    ipCount:              whois?.ipGeo?.length || 0,
    // SSL
    sslScanned:           ssl?.summary?.total || 0,
    sslExpired:           ssl?.summary?.expired || 0,
    sslExpiring:          ssl?.summary?.expiring || 0,
    sslValid:             ssl?.summary?.valid || 0,
  };
}
