#!/bin/bash

# ReconScan Platform Setup Script
# ────────────────────────────────────────────────────────────────

set -e

echo ""
echo "  ⬡  ReconScan — Security Assessment Platform"
echo "  ─────────────────────────────────────────────"
echo ""

MODE=${1:-"dev"}

install_tools_linux() {
  echo "  [+] Installing security tools..."
  # nmap
  if ! command -v nmap &>/dev/null; then
    sudo apt-get install -y nmap 2>/dev/null || sudo yum install -y nmap 2>/dev/null || true
  fi

  # ProjectDiscovery tools (Go-based)
  if command -v go &>/dev/null; then
    echo "  [+] Installing subfinder..."
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || true
    echo "  [+] Installing httpx..."
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || true
    echo "  [+] Installing dnsx..."
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest 2>/dev/null || true
    echo "  [+] Installing nuclei..."
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || true
  else
    echo "  [!] Go not found. ProjectDiscovery tools (subfinder/httpx/dnsx) won't be available."
    echo "      The platform will fall back to built-in Node.js DNS/HTTP probing."
    echo "      Install Go from https://go.dev/dl/ for full scan capabilities."
  fi
}

install_tools_mac() {
  if command -v brew &>/dev/null; then
    brew install nmap 2>/dev/null || true
    brew install go 2>/dev/null || true
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || true
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || true
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest 2>/dev/null || true
  fi
}

if [[ "$MODE" == "docker" ]]; then
  echo "  [+] Starting with Docker Compose..."
  docker-compose up --build
  exit 0
fi

# Detect OS
OS=$(uname -s)
if [[ "$OS" == "Linux" ]]; then
  install_tools_linux
elif [[ "$OS" == "Darwin" ]]; then
  install_tools_mac
fi

echo ""
echo "  [+] Installing Node.js dependencies..."
cd backend && npm install && cd ..
cd frontend && npm install && cd ..

echo ""
echo "  [+] Tool availability check:"
for tool in nmap subfinder httpx dnsx nuclei; do
  if command -v $tool &>/dev/null; then
    echo "      ✓  $tool"
  else
    echo "      ✗  $tool (not found — will use fallback)"
  fi
done

echo ""
echo "  ─────────────────────────────────────────────"
echo "  [+] Starting ReconScan..."
echo ""
echo "      Backend:  http://localhost:3001"
echo "      Frontend: http://localhost:3000"
echo ""

# Start backend
cd backend && node server.js &
BACKEND_PID=$!

# Start frontend
cd ../frontend && npm start &
FRONTEND_PID=$!

echo "  [+] Services started. Press Ctrl+C to stop."

trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit" INT TERM
wait
