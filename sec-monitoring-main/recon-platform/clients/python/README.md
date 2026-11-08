# ReconScan Python SDK & CLI

Zero-dependency Python client and CLI for the ReconScan Vulnerability Scanner API. Requires Python 3.8+ (uses standard library only: `urllib`, `json`, `argparse`).

---

## 🚀 Quickstart via CLI

No `pip install` required! Run directly with Python:

```bash
# 1. Check API server health
python reconscan.py health

# 2. List all scans
python reconscan.py list

# 3. Start a full scan and watch live progress
python reconscan.py scan example.com --watch

# 4. Start a targeted scan (specific modules only)
python reconscan.py scan example.com --mode single --modules portScan,sslScan,dnsAssessment --watch

# 5. Check status of a scan by ID
python reconscan.py status <scan-id>

# 6. Download standalone HTML or PDF report
python reconscan.py report <scan-id> --format html -o report.html
python reconscan.py report <scan-id> --format pdf -o report.pdf

# 7. Compare two scans (diff findings & score change)
python reconscan.py compare <scan-id-1> <scan-id-2>
```

### Authentication & Custom API URL
You can pass custom API settings via command line flags or environment variables:
```bash
export RECONSCAN_URL="http://your-scanner-host:3001"
export RECONSCAN_API_KEY="your-secret-api-key"

python reconscan.py scan target.com --watch
```
Or with flags:
```bash
python reconscan.py --url http://your-host:3001 --api-key my-key scan target.com
```

---

## 💻 Programmatic Python SDK Usage

```python
from reconscan import ReconScanClient

# Initialize client
client = ReconScanClient(
    base_url="http://localhost:3001",
    api_key="my-api-key"  # Optional
)

# 1. Start a scan
scan = client.start_scan(
    domain="example.com",
    scan_mode="full",  # 'full' or 'single'
    selected_modules=["sslScan", "portScan", "vulnAssessment"]  # Or None for all
)
scan_id = scan["scanId"]

# 2. Poll until complete
result = client.poll_scan(scan_id, interval_seconds=2)
print("Score:", result["riskScore"]["score"], "Grade:", result["riskScore"]["grade"])

# 3. Iterate through findings
for f in result.get("findings", []):
    print(f"[{f['severity'].upper()}] ({f.get('confidence')}) {f['title']}")

# 4. Save HTML report
html = client.get_report_html(scan_id)
with open("report.html", "w", encoding="utf-8") as f:
    f.write(html)
```

