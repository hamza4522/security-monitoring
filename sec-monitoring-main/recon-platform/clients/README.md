# ReconScan API Clients & SDKs

This directory contains standalone, zero-dependency clients and command-line interfaces for interacting with the ReconScan Vulnerability Scanner API.

Whether you want to integrate scans into CI/CD pipelines, automate security checks, or trigger scans from terminal scripts, you can use either Python or Node.js without installing third-party dependencies.

---

## 📁 Available Clients

| Client | Directory | Prerequisites | Description |
| :--- | :--- | :--- | :--- |
| **Python SDK & CLI** | [`python/`](./python) | Python 3.8+ (No pip install needed) | Python class `ReconScanClient` and CLI `reconscan.py` using standard `urllib`. |
| **Node.js SDK & CLI** | [`nodejs/`](./nodejs) | Node.js 18+ (No npm install needed) | Node.js class `ReconScanClient` and CLI `reconscan.js` using native `fetch`. |

---

## ⚡ Quick Comparisons

### 1. Launch a Scan & Watch Progress

**Using Python:**
```bash
python clients/python/reconscan.py scan example.com --watch
```

**Using Node.js:**
```bash
node clients/nodejs/reconscan.js scan example.com --watch
```

---

### 2. Export Standalone HTML Report

**Using Python:**
```bash
python clients/python/reconscan.py report <scan-id> --format html -o report.html
```

**Using Node.js:**
```bash
node clients/nodejs/reconscan.js report <scan-id> --format html -o report.html
```

---

### 3. Server Health & Status Check

**Using Python:**
```bash
python clients/python/reconscan.py health
```

**Using Node.js:**
```bash
node clients/nodejs/reconscan.js health
```

---

## 🔐 API Key Authentication

If `API_KEY` is configured in your server `.env`, provide it via `--api-key` or set the environment variable:

```bash
# Environment variables supported by both clients
export RECONSCAN_URL="http://localhost:3001"
export RECONSCAN_API_KEY="your-secret-api-key"

# Python
python clients/python/reconscan.py list

# Node.js
node clients/nodejs/reconscan.js list
```

