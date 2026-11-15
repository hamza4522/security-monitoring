#!/usr/bin/env python3
"""
ReconScan Python SDK & CLI
A lightweight, zero-dependency Python client for the ReconScan Vulnerability Scanner API.
Supports Python 3.8+ using only standard library (urllib, json, argparse, time).
"""

import os
import sys
import time
import json
import argparse
import urllib.request
import urllib.error
from typing import Dict, Any, Optional, List, Callable


class ReconScanClient:
    """Python API Client for ReconScan."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: int = 30
    ):
        """
        Initialize the ReconScan API Client.

        :param base_url: Base URL of ReconScan API (default: http://localhost:3001)
        :param api_key: Optional API key for x-api-key authentication
        :param timeout: HTTP request timeout in seconds
        """
        self.base_url = (base_url or os.getenv("RECONSCAN_URL") or "http://localhost:3001").rstrip("/")
        self.api_key = api_key or os.getenv("RECONSCAN_API_KEY") or None
        self.timeout = timeout

    def _request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None,
        is_json: bool = True
    ) -> Any:
        url = f"{self.base_url}{endpoint}"
        headers = {
            "User-Agent": "ReconScan-Python-Client/2.0",
            "Accept": "application/json" if is_json else "*/*",
        }
        if self.api_key:
            headers["x-api-key"] = self.api_key

        body = None
        if data is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(data).encode("utf-8")

        req = urllib.request.Request(url, data=body, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                raw = response.read()
                if is_json:
                    return json.loads(raw.decode("utf-8"))
                return raw
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="ignore")
            try:
                err_json = json.loads(err_body)
                msg = err_json.get("error", err_body)
            except Exception:
                msg = err_body or str(e)
            raise RuntimeError(f"API Error [{e.code}] {msg}") from e
        except urllib.error.URLError as e:
            raise RuntimeError(f"Connection failed to {url}: {e.reason}") from e

    # ── Health ───────────────────────────────────────────────────────────────

    def health(self) -> Dict[str, Any]:
        """Check API server health."""
        return self._request("GET", "/health")

    # ── Scans ─────────────────────────────────────────────────────────────────

    def start_scan(
        self,
        domain: str,
        scan_mode: str = "full",
        selected_modules: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Start a new vulnerability scan.

        :param domain: Target domain (e.g. example.com)
        :param scan_mode: 'full' (with subdomain discovery) or 'single' (target domain only)
        :param selected_modules: List of specific module names to execute (None for all)
        :return: Dict containing scanId, status, scanMode, selectedModules
        """
        payload = {
            "domain": domain,
            "scanMode": scan_mode,
            "selectedModules": selected_modules or []
        }
        return self._request("POST", "/api/scan/start", data=payload)

    def get_scan(self, scan_id: str) -> Dict[str, Any]:
        """Get scan status, modules, findings, and risk score."""
        return self._request("GET", f"/api/scan/{scan_id}")

    def list_scans(self) -> List[Dict[str, Any]]:
        """List all past and active scans."""
        return self._request("GET", "/api/scan")

    def cancel_scan(self, scan_id: str) -> Dict[str, Any]:
        """Cancel a running scan."""
        return self._request("DELETE", f"/api/scan/{scan_id}")

    def compare_scans(self, scan_id_a: str, scan_id_b: str) -> Dict[str, Any]:
        """Compare results of two scans (diff findings & risk score change)."""
        return self._request("GET", f"/api/scan/compare?a={scan_id_a}&b={scan_id_b}")

    def poll_scan(
        self,
        scan_id: str,
        interval_seconds: float = 2.0,
        timeout_seconds: float = 600.0,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None
    ) -> Dict[str, Any]:
        """
        Poll until scan completes or fails.

        :param scan_id: The ID of the scan
        :param interval_seconds: Polling interval
        :param timeout_seconds: Maximum time to wait
        :param progress_callback: Optional callback receiving current scan state on each poll
        :return: Completed scan object
        """
        start_time = time.time()
        last_progress = -1

        while True:
            scan = self.get_scan(scan_id)
            status = scan.get("status")
            progress = scan.get("progress", 0)

            if progress_callback:
                progress_callback(scan)
            elif progress != last_progress:
                last_progress = progress
                sys.stdout.write(f"\r[*] Scan progress: {progress}% [Status: {status}]")
                sys.stdout.flush()

            if status in ("complete", "error", "cancelled"):
                if not progress_callback:
                    sys.stdout.write("\n")
                return scan

            if (time.time() - start_time) > timeout_seconds:
                raise TimeoutError(f"Scan {scan_id} timed out after {timeout_seconds}s")

            time.sleep(interval_seconds)

    # ── Reports ───────────────────────────────────────────────────────────────

    def get_report_json(self, scan_id: str) -> Dict[str, Any]:
        """Download scan report in structured JSON format."""
        return self._request("GET", f"/api/report/json/{scan_id}")

    def get_report_html(self, scan_id: str) -> str:
        """Download scan report in standalone HTML format."""
        content = self._request("GET", f"/api/report/html/{scan_id}", is_json=False)
        return content.decode("utf-8")

    def get_report_pdf(self, scan_id: str) -> bytes:
        """Download scan report in PDF binary format."""
        return self._request("GET", f"/api/report/pdf/{scan_id}", is_json=False)


# ── CLI Interface ─────────────────────────────────────────────────────────────

def _format_findings_table(findings: List[Dict[str, Any]]) -> str:
    if not findings:
        return "  No vulnerabilities found! Clean scan."

    lines = []
    lines.append(f"  {'SEVERITY':<10} {'CONFIDENCE':<12} {'TITLE':<45} {'MODULE'}")
    lines.append("  " + "-" * 85)

    for f in findings:
        sev = f.get("severity", "info").upper()
        conf = f.get("confidence", "unverified")
        title = f.get("title", "Untitled")[:43]
        mod = f.get("module", "")
        lines.append(f"  {sev:<10} {conf:<12} {title:<45} {mod}")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="ReconScan Vulnerability Scanner CLI & Python Client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python reconscan.py health
  python reconscan.py list
  python reconscan.py scan example.com --watch
  python reconscan.py scan example.com --mode single --modules portScan,sslScan
  python reconscan.py status <scan-id>
  python reconscan.py report <scan-id> --format html -o report.html
  python reconscan.py compare <scan-id-1> <scan-id-2>
"""
    )
    parser.add_argument("--url", default=None, help="ReconScan API URL (default: http://localhost:3001)")
    parser.add_argument("--api-key", default=None, help="API key for authentication (or RECONSCAN_API_KEY env)")

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # health
    subparsers.add_parser("health", help="Check API server health")

    # list
    subparsers.add_parser("list", help="List all scans")

    # scan
    scan_p = subparsers.add_parser("scan", help="Start a new scan")
    scan_p.add_argument("domain", help="Target domain (e.g. example.com)")
    scan_p.add_argument("--mode", choices=["full", "single"], default="full", help="Scan mode")
    scan_p.add_argument("--modules", default=None, help="Comma-separated module keys to run")
    scan_p.add_argument("--watch", action="store_true", help="Watch progress until completion")

    # status
    status_p = subparsers.add_parser("status", help="Get scan details")
    status_p.add_argument("scan_id", help="Scan UUID")

    # report
    report_p = subparsers.add_parser("report", help="Fetch scan report")
    report_p.add_argument("scan_id", help="Scan UUID")
    report_p.add_argument("--format", choices=["json", "html", "pdf"], default="json", help="Report format")
    report_p.add_argument("-o", "--output", help="Save report to file path")

    # compare
    cmp_p = subparsers.add_parser("compare", help="Compare two scans")
    cmp_p.add_argument("scan_a", help="First scan UUID (baseline)")
    cmp_p.add_argument("scan_b", help="Second scan UUID (target)")

    # cancel
    cancel_p = subparsers.add_parser("cancel", help="Cancel a scan")
    cancel_p.add_argument("scan_id", help="Scan UUID")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    client = ReconScanClient(base_url=args.url, api_key=args.api_key)

    try:
        if args.command == "health":
            h = client.health()
            print(json.dumps(h, indent=2))

        elif args.command == "list":
            scans = client.list_scans()
            print(f"Found {len(scans)} scan(s):")
            print(f"{'SCAN ID':<38} {'DOMAIN':<25} {'STATUS':<12} {'STARTED AT'}")
            print("-" * 95)
            for s in scans:
                print(f"{s['id']:<38} {s['domain']:<25} {s['status']:<12} {s['startedAt'][:19]}")

        elif args.command == "scan":
            modules = [m.strip() for m in args.modules.split(",")] if args.modules else []
            res = client.start_scan(args.domain, scan_mode=args.mode, selected_modules=modules)
            scan_id = res["scanId"]
            print(f"[+] Scan started! ID: {scan_id} (Mode: {args.mode})")

            if args.watch:
                completed = client.poll_scan(scan_id)
                score_info = completed.get("riskScore") or {}
                findings = completed.get("findings") or []
                print(f"\n[+] Scan Complete for {args.domain}!")
                print(f"    Risk Score: {score_info.get('score', 'N/A')}/100 (Grade: {score_info.get('grade', 'N/A')})")
                print(f"    Findings: {len(findings)} total\n")
                print(_format_findings_table(findings))

        elif args.command == "status":
            scan = client.get_scan(args.scan_id)
            score_info = scan.get("riskScore") or {}
            findings = scan.get("findings") or []
            print(f"Target:      {scan.get('domain')}")
            print(f"Status:      {scan.get('status')} ({scan.get('progress', 0)}%)")
            print(f"Started:     {scan.get('startedAt')}")
            print(f"Risk Score:  {score_info.get('score', 'N/A')}/100 (Grade: {score_info.get('grade', 'N/A')})")
            print(f"\nFindings ({len(findings)}):")
            print(_format_findings_table(findings))

        elif args.command == "report":
            if args.format == "json":
                rep = client.get_report_json(args.scan_id)
                if args.output:
                    with open(args.output, "w", encoding="utf-8") as f:
                        json.dump(rep, f, indent=2)
                    print(f"[+] JSON report saved to {args.output}")
                else:
                    print(json.dumps(rep, indent=2))
            elif args.format == "html":
                html = client.get_report_html(args.scan_id)
                out = args.output or f"report-{args.scan_id[:8]}.html"
                with open(out, "w", encoding="utf-8") as f:
                    f.write(html)
                print(f"[+] HTML report saved to {out}")
            elif args.format == "pdf":
                pdf = client.get_report_pdf(args.scan_id)
                out = args.output or f"report-{args.scan_id[:8]}.pdf"
                with open(out, "wb") as f:
                    f.write(pdf)
                print(f"[+] PDF report saved to {out}")

        elif args.command == "compare":
            cmp_res = client.compare_scans(args.scan_a, args.scan_b)
            print(json.dumps(cmp_res, indent=2))

        elif args.command == "cancel":
            c = client.cancel_scan(args.scan_id)
            print(f"[+] Scan {args.scan_id} cancelled: {c}")

    except Exception as e:
        sys.stderr.write(f"\n[!] Error: {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()

