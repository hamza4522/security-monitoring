#!/usr/bin/env node
'use strict';
/**
 * ReconScan Node.js CLI
 * Zero-dependency CLI runner.
 */

const fs = require('fs');
const path = require('path');
const { ReconScanClient } = require('./index');

function printUsage() {
  console.log(`
ReconScan CLI (Node.js)

Usage:
  node reconscan.js <command> [options]

Commands:
  health                                 Check API server health
  list                                   List recent scans
  scan <domain> [options]                Start a new scan
  status <scanId>                        Get status and findings of a scan
  report <scanId> [--format json|html|pdf] [-o output.ext]
  compare <scanId1> <scanId2>            Compare two completed scans
  cancel <scanId>                        Cancel a running scan

Options for 'scan':
  --mode <full|single>                   Scan mode (default: full)
  --modules <mod1,mod2>                  Comma-separated list of modules
  --watch                                Watch scan progress until complete

Global Options:
  --url <url>                            API base URL (default: http://localhost:3001 or RECONSCAN_URL)
  --api-key <key>                        API key (or RECONSCAN_API_KEY)
`);
}

function parseArgs() {
  const argv = process.argv.slice(2);
  const options = {
    url: process.env.RECONSCAN_URL || 'http://localhost:3001',
    apiKey: process.env.RECONSCAN_API_KEY || null,
    mode: 'full',
    modules: [],
    watch: false,
    format: 'json',
    output: null,
    positionals: [],
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--url' && i + 1 < argv.length) options.url = argv[++i];
    else if (arg === '--api-key' && i + 1 < argv.length) options.apiKey = argv[++i];
    else if (arg === '--mode' && i + 1 < argv.length) options.mode = argv[++i];
    else if (arg === '--modules' && i + 1 < argv.length) options.modules = argv[++i].split(',').map(s => s.trim());
    else if (arg === '--watch') options.watch = true;
    else if (arg === '--format' && i + 1 < argv.length) options.format = argv[++i];
    else if ((arg === '-o' || arg === '--output') && i + 1 < argv.length) options.output = argv[++i];
    else if (!arg.startsWith('-')) options.positionals.push(arg);
  }

  return options;
}

function printFindings(findings) {
  if (!findings || findings.length === 0) {
    console.log('  No vulnerabilities found! Clean scan.');
    return;
  }
  console.log(`  ${'SEVERITY'.padEnd(10)} ${'CONFIDENCE'.padEnd(12)} ${'TITLE'.padEnd(45)} MODULE`);
  console.log('  ' + '-'.repeat(85));
  for (const f of findings) {
    const sev = (f.severity || 'info').toUpperCase().padEnd(10);
    const conf = (f.confidence || 'unverified').padEnd(12);
    const title = (f.title || 'Untitled').slice(0, 43).padEnd(45);
    const mod = f.module || '';
    console.log(`  ${sev} ${conf} ${title} ${mod}`);
  }
}

async function main() {
  const opts = parseArgs();
  const command = opts.positionals[0];

  if (!command) {
    printUsage();
    process.exit(1);
  }

  const client = new ReconScanClient({ baseUrl: opts.url, apiKey: opts.apiKey });

  try {
    switch (command) {
      case 'health': {
        const h = await client.health();
        console.log(JSON.stringify(h, null, 2));
        break;
      }

      case 'list': {
        const scans = await client.listScans();
        console.log(`Found ${scans.length} scan(s):`);
        console.log(`${'SCAN ID'.padEnd(38)} ${'DOMAIN'.padEnd(25)} ${'STATUS'.padEnd(12)} STARTED AT`);
        console.log('-'.repeat(95));
        for (const s of scans) {
          console.log(`${s.id.padEnd(38)} ${s.domain.padEnd(25)} ${s.status.padEnd(12)} ${s.startedAt.slice(0, 19)}`);
        }
        break;
      }

      case 'scan': {
        const domain = opts.positionals[1];
        if (!domain) {
          console.error('[!] Error: Domain is required. Example: node reconscan.js scan example.com');
          process.exit(1);
        }

        const res = await client.startScan(domain, {
          scanMode: opts.mode,
          selectedModules: opts.modules,
        });

        console.log(`[+] Scan started! ID: ${res.scanId} (Mode: ${opts.mode})`);

        if (opts.watch) {
          let lastProg = -1;
          const completed = await client.waitForScan(res.scanId, {
            onProgress: (s) => {
              if (s.progress !== lastProg) {
                lastProg = s.progress;
                process.stdout.write(`\r[*] Progress: ${s.progress}% [Status: ${s.status}]`);
              }
            },
          });
          process.stdout.write('\n');
          const score = completed.riskScore || {};
          const findings = completed.findings || [];
          console.log(`\n[+] Scan Complete for ${domain}!`);
          console.log(`    Risk Score: ${score.score ?? 'N/A'}/100 (Grade: ${score.grade ?? 'N/A'})`);
          console.log(`    Findings:   ${findings.length} total\n`);
          printFindings(findings);
        }
        break;
      }

      case 'status': {
        const scanId = opts.positionals[1];
        if (!scanId) {
          console.error('[!] Error: Scan ID is required.');
          process.exit(1);
        }
        const scan = await client.getScan(scanId);
        const score = scan.riskScore || {};
        const findings = scan.findings || [];
        console.log(`Target:      ${scan.domain}`);
        console.log(`Status:      ${scan.status} (${scan.progress}%)`);
        console.log(`Started:     ${scan.startedAt}`);
        console.log(`Risk Score:  ${score.score ?? 'N/A'}/100 (Grade: ${score.grade ?? 'N/A'})`);
        console.log(`\nFindings (${findings.length}):`);
        printFindings(findings);
        break;
      }

      case 'report': {
        const scanId = opts.positionals[1];
        if (!scanId) {
          console.error('[!] Error: Scan ID is required.');
          process.exit(1);
        }
        if (opts.format === 'json') {
          const rep = await client.getReportJson(scanId);
          if (opts.output) {
            fs.writeFileSync(opts.output, JSON.stringify(rep, null, 2), 'utf-8');
            console.log(`[+] JSON report saved to ${opts.output}`);
          } else {
            console.log(JSON.stringify(rep, null, 2));
          }
        } else if (opts.format === 'html') {
          const html = await client.getReportHtml(scanId);
          const out = opts.output || `report-${scanId.slice(0, 8)}.html`;
          fs.writeFileSync(out, html, 'utf-8');
          console.log(`[+] HTML report saved to ${out}`);
        } else if (opts.format === 'pdf') {
          const pdf = await client.getReportPdf(scanId);
          const out = opts.output || `report-${scanId.slice(0, 8)}.pdf`;
          fs.writeFileSync(out, pdf);
          console.log(`[+] PDF report saved to ${out}`);
        }
        break;
      }

      case 'compare': {
        const a = opts.positionals[1];
        const b = opts.positionals[2];
        if (!a || !b) {
          console.error('[!] Error: Two scan IDs are required. Example: compare <idA> <idB>');
          process.exit(1);
        }
        const cmp = await client.compareScans(a, b);
        console.log(JSON.stringify(cmp, null, 2));
        break;
      }

      case 'cancel': {
        const scanId = opts.positionals[1];
        const res = await client.cancelScan(scanId);
        console.log(`[+] Scan ${scanId} cancelled:`, res);
        break;
      }

      default:
        console.error(`[!] Unknown command: ${command}`);
        printUsage();
        process.exit(1);
    }
  } catch (err) {
    console.error(`\n[!] Error: ${err.message}`);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

