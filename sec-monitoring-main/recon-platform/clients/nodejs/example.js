'use strict';
/**
 * Example: Using ReconScan Node.js SDK programmatically.
 */

const { ReconScanClient } = require('./index');

async function run() {
  const client = new ReconScanClient({
    baseUrl: 'http://localhost:3001',
    apiKey: null, // Set if API_KEY is configured on server
  });

  // 1. Health check
  const health = await client.health();
  console.log(`[*] API Health: ${health.status} (Uptime: ${health.uptime}s, Scans: ${health.scans})`);

  // 2. Launch scan
  const target = 'example.com';
  console.log(`[*] Starting targeted scan on ${target}...`);
  const { scanId } = await client.startScan(target, {
    scanMode: 'single',
    selectedModules: ['sslScan', 'dnsAssessment', 'portScan'],
  });
  console.log(`[+] Scan started with ID: ${scanId}`);

  // 3. Poll with progress updates
  console.log('[*] Waiting for scan completion...');
  const result = await client.waitForScan(scanId, {
    intervalMs: 2000,
    onProgress: (s) => process.stdout.write(`\r[*] Progress: ${s.progress}% [${s.status}]`),
  });
  console.log('\n[+] Scan finished!');

  // 4. Inspect results
  const score = result.riskScore || {};
  console.log(`    Risk Score: ${score.score}/100 (Grade: ${score.grade})`);
  console.log(`    Findings:   ${result.findings?.length || 0}`);

  for (const f of result.findings || []) {
    console.log(`    - [${f.severity.toUpperCase()}] (${f.confidence || 'unverified'}) ${f.title}`);
  }
}

run().catch(console.error);

