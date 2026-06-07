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
const { calculateRiskScore }   = require('../utils/riskScoring');

module.exports = (scans, broadcast, alertEngine = null) => {
  const router = express.Router();

  // Start a new scan
  router.post('/start', async (req, res) => {
    const { domain, modules = ['all'] } = req.body;

    if (!domain) {
      return res.status(400).json({ error: 'Domain is required' });
    }

    // Basic domain validation
    const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    if (!domainRegex.test(domain)) {
      return res.status(400).json({ error: 'Invalid domain format' });
    }

    const scanId = uuidv4();
    const scan = {
      id: scanId,
      domain,
      status: 'running',
      progress: 0,
      startedAt: new Date().toISOString(),
      completedAt: null,
      modules: {
        whoisLookup:       { status: 'pending', data: null },
        assetDiscovery:    { status: 'pending', data: null },
        dnsAssessment:     { status: 'pending', data: null },
        portScan:          { status: 'pending', data: null },
        serviceFingerprint:{ status: 'pending', data: null },
        webTechFingerprint:{ status: 'pending', data: null },
        vulnAssessment:    { status: 'pending', data: null },
        wapitiscan:        { status: 'pending', data: null },
        cmsVulnScan:       { status: 'pending', data: null },
      },
      findings: [],
      riskScore: null,
      summary: null,
    };

    scans.set(scanId, scan);
    res.json({ scanId, status: 'started' });

    // Run modules asynchronously
    runScanPipeline(scanId, domain, scan, scans, broadcast, alertEngine);
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

const MODULE_TIMEOUT = 90000;  // 90 seconds per module
const GLOBAL_TIMEOUT = 300000; // 5 minutes for the entire scan

async function runScanPipeline(scanId, domain, scan, scans, broadcast, alertEngine) {
  const emit = (event, data) => {
    broadcast(scanId, { event, ...data });
  };

  const updateModule = (moduleName, status, data = null) => {
    scan.modules[moduleName] = { status, data };
    scans.set(scanId, scan);
  };

  const moduleList = [
    { key: 'whoisLookup',       label: 'WHOIS & IP Intel',         runner: runWhoisLookup,         weight: 10 },
    { key: 'assetDiscovery',    label: 'Asset Discovery',          runner: runAssetDiscovery,      weight: 11 },
    { key: 'dnsAssessment',     label: 'DNS Assessment',           runner: runDNSAssessment,        weight: 11 },
    { key: 'portScan',          label: 'Port Scanning',            runner: runPortScan,             weight: 12 },
    { key: 'serviceFingerprint',label: 'Service Fingerprinting',   runner: runServiceFingerprint,   weight: 12 },
    { key: 'webTechFingerprint',label: 'Web Tech Fingerprinting',  runner: runWebTechFingerprint,   weight: 11 },
    { key: 'vulnAssessment',    label: 'Vulnerability Assessment', runner: runVulnAssessment,       weight: 11 },
    { key: 'wapitiscan',        label: 'Active Web Attacks',       runner: runWapitiScan,           weight: 11 },
    { key: 'cmsVulnScan',       label: 'CMS Vulnerability Scan',  runner: runCMSVulnScan,          weight: 11 },
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
        // Per-module timeout wrapper
        const result = await withTimeout(
          mod.runner(domain, (msg) => {
            emit('module_progress', { module: mod.key, message: msg });
          }),
          MODULE_TIMEOUT,
          mod.label
        );

        updateModule(mod.key, 'complete', result);
        completedWeight += mod.weight;
        scan.progress = completedWeight;

        // Collect findings
        if (result && result.findings) {
          scan.findings.push(...result.findings);
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

function buildSummary(scan) {
  const { modules } = scan;
  const whois  = modules.whoisLookup?.data;
  const assets = modules.assetDiscovery?.data;
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
  };
}
