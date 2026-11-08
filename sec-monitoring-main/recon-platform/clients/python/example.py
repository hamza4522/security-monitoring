#!/usr/bin/env python3
"""
Example: Using the ReconScan Python SDK programmatically.
"""

from reconscan import ReconScanClient

def main():
    # 1. Initialize client
    client = ReconScanClient(base_url="http://localhost:3001", api_key=None)

    # 2. Check health
    health = client.health()
    print(f"[*] API Health: {health.get('status')} (Uptime: {health.get('uptime')}s)")

    # 3. Start a scan
    target = "example.com"
    print(f"[*] Starting single-domain scan for {target}...")
    res = client.start_scan(
        domain=target,
        scan_mode="single",
        selected_modules=["sslScan", "dnsAssessment", "portScan"]
    )
    scan_id = res["scanId"]
    print(f"[+] Scan launched with ID: {scan_id}")

    # 4. Wait for scan to finish
    print("[*] Waiting for results...")
    result = client.poll_scan(scan_id, interval_seconds=2)

    # 5. Inspect findings and risk score
    score = result.get("riskScore", {})
    print(f"\n[+] Scan finished!")
    print(f"    Risk Score: {score.get('score')}/100")
    print(f"    Grade:      {score.get('grade')} ({score.get('label')})")
    print(f"    Findings:   {len(result.get('findings', []))}")

    for f in result.get("findings", []):
        print(f"    - [{f.get('severity').upper()}] ({f.get('confidence')}) {f.get('title')}")

    # 6. Fetch full HTML report
    html_report = client.get_report_html(scan_id)
    with open("example-report.html", "w", encoding="utf-8") as f:
        f.write(html_report)
    print("\n[+] Report exported to example-report.html")

if __name__ == "__main__":
    main()

