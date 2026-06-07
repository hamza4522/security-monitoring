# ReconScan - Security Assessment Platform 🚨

ReconScan is an agentless, full-stack, modular web reconnaissance and active vulnerability scanning platform built in Node.js and React. It brings powerful security scanning features like asset discovery, port scanning, web application attack simulations, CMS vulnerability scanning, and an advanced alerting engine—all accessible via a beautiful, responsive dark-mode dashboard.

---

## 🛠️ Installation & Setup

### Prerequisites
*   **Node.js**: v18 or higher recommended.
*   **Wapiti**: Required for the Web Attacks module. Wapiti must be installed and accessible in your system's PATH. (`pip install wapiti3` or via OS package manager)
*   **Nmap** (Optional but recommended): Required for accurate port scanning. If omitted, the tool falls back to simple socket connection checks.

### 1. Clone & Install Dependencies
First, install dependencies for both the frontend and backend.

```bash
# Install backend dependencies
cd recon-platform/backend
npm install

# Install frontend dependencies
cd ../frontend
npm install
```

### 2. Start the Backend Server
The backend handles all the heavy lifting, orchestrating scans, broadcasting updates via WebSockets, and managing the Alerting Engine.

```bash
cd recon-platform/backend
npm start
# The backend will start on http://localhost:3001
```

### 3. Start the Frontend App
In a new terminal window, start the React application.

```bash
cd recon-platform/frontend
npm start
# The frontend will be available at http://localhost:3000
```

---

## 🚀 Features & Functionalities

### 1. Comprehensive Modular Scanning Pipeline
The platform uses an intelligent pipeline that executes sequentially and concurrently depending on the module requirements:

1.  **Asset Discovery**: Subdomain enumeration (using crt.sh) to identify the attack surface.
2.  **DNS & Email Security**: Analyzes MX/TXT records and checks for SPF/DMARC configurations to detect email spoofing risks.
3.  **Port Scanning**: Uses Nmap (or fallback socket probing) to identify open ports and services (e.g., SSH, FTP, HTTP, Database ports).
4.  **Service Fingerprinting**: Banner grabs open ports to identify underlying software and versions.
5.  **Web Tech Fingerprinting**: Parses HTTP headers and HTML metadata (powered by `wappalyzer-core` logic) to detect JS frameworks, backend languages, and web servers.
6.  **Vulnerability Assessment**: Performs dozens of checks including HTTP Security Headers, Cookie Flags, Wildcard CORS, HTTP methods, SSL/TLS certificate validity, sensitive file exposure (`/.env`, `/.git`, etc.), and **matches server versions against 50+ high-profile CVEs** (Log4Shell, Spring4Shell, Citrix, F5, etc.).
7.  **CMS Vulnerability Scanner**: Specialized module that detects CMS platforms (WordPress, Drupal, Joomla, Magento, Laravel, etc.) and runs targeted exploit checks (e.g., probing for exposed `wp-config.php.bak`, Laravel `telescope` exposure, etc.).
8.  **Active Web Attacks**: Integrates with Wapiti to actively fuzz parameters and simulate attacks like XSS, SQLi, LFI, and Command Injection.

### 2. Advanced Risk Scoring System
The engine dynamically grades target risks from **A** to **F**. 
*   Scores are augmented based on OWASP Top 10 categories mapping.
*   Certain high-severity issues (like active Web Attacks or critical CVE hits) heavily impact the grade.
*   Risk trending charts track historical risk over time for your targets on the dashboard.

### 3. Real-Time Alerting System & Rule Engine
Automatically notify your team when specific security events happen.
*   **Rule Triggers**: Alert on High/Critical severity findings, overall Risk Score drops, specific attack types detected, or newly discovered open ports.
*   **Multiple Channels**: Supports in-browser push notifications, generic Webhooks, Slack Webhooks, Discord Webhooks, and SMTP Email dispatch.
*   **Alert Dashboard**: A dedicated view to manage alert history, read/unread states, and configure rules.

### 4. Rich Export & Reporting
*   **JSON Export**: Download raw finding data for integrations or API parsing.
*   **Markdown Reports**: Generate clean, professional Markdown reports with risk summaries, methodology explanations, and formatted findings suitable for bug bounty submissions or internal documentation.
*   **Copy to Clipboard**: Quickly copy findings directly from the UI.

### 5. Beautiful & Modern UI
*   **Dark / Light Theme**: Fully supported with a smooth transition.
*   **Global Search (Ctrl+K)**: Instantly search across all scans and findings globally.
*   **Keyboard Shortcuts**: Press `?` anytime to view the shortcut menu.
*   **Toast Notifications**: Beautiful, non-blocking UI notifications for system events and scan completion.
*   **Live Event Log**: Watch the scanner work in real-time as WebSocket events stream into the UI.

---

## ⚙️ Configuration Notes
*   **Email Alerts**: To use the SMTP Email alert channel, ensure `nodemailer` is installed in the backend (`npm install nodemailer`) and configure the credentials via the UI Alert Settings page.
*   **Persistence**: Scans, Alerts, and Configurations are currently stored in-memory or in flat JSON files for easy setup.

## 🛡️ Disclaimer
This tool is built for **educational purposes and authorized security assessments only**. Ensure you have explicit permission from the asset owner before initiating any active scans or attacks.
