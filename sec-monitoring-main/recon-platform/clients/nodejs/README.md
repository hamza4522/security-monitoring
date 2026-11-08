# ReconScan Node.js SDK & CLI

Zero-dependency Node.js client and CLI tool for the ReconScan Vulnerability Scanner API. Works on Node.js 18+ using native `fetch`.

---

## 🚀 CLI Usage

Run without installing any external packages:

```bash
# 1. Health check
node reconscan.js health

# 2. List all scans
node reconscan.js list

# 3. Start a full scan and watch live progress
node reconscan.js scan example.com --watch

# 4. Start targeted scan (specific modules only)
node reconscan.js scan example.com --mode single --modules portScan,sslScan,dnsAssessment --watch

# 5. Check status of scan
node reconscan.js status <scan-id>

# 6. Download standalone HTML or PDF report
node reconscan.js report <scan-id> --format html -o report.html
node reconscan.js report <scan-id> --format pdf -o report.pdf

# 7. Compare two scans
node reconscan.js compare <scan-id-1> <scan-id-2>
```

### Global Install / CLI Symlink
You can link this package globally to use `reconscan` anywhere on your machine:
```bash
npm link
reconscan scan example.com --watch
```

---

## 💻 Programmatic Node.js SDK

```javascript
const { ReconScanClient } = require('./index');

const client = new ReconScanClient({
  baseUrl: 'http://localhost:3001',
  apiKey: process.env.RECONSCAN_API_KEY || null,
});

async function main() {
  // Start scan
  const { scanId } = await client.startScan('example.com', {
    scanMode: 'full',
  });

  // Wait for results
  const result = await client.waitForScan(scanId, {
    onProgress: (s) => console.log(`Progress: ${s.progress}%`),
  });

  console.log('Final Score:', result.riskScore.score);
  console.log('Total Findings:', result.findings.length);
}

main().catch(console.error);
```

