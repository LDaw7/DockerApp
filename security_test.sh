#!/bin/bash
# Security scans - requires ./setup.sh first
# Usage: ./security_test.sh | ./security_test.sh --quick

set -eo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
REPORTS="./security-reports"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
header()      { echo -e "\n${BLUE}════════════════════════════════════════════════════════════════${NC}\n${BLUE}  $1${NC}\n${BLUE}════════════════════════════════════════════════════════════════${NC}"; }

require_tool() { command -v "$1" &>/dev/null || { log_warn "$1 not found: $2"; return 1; }; }

check_app() {
    curl -sk https://localhost/health | grep -q "healthy" || { echo "App not running. Run ./setup.sh first"; exit 1; }
    log_success "App running"
}

run_pytest() {
    header "Pytest"
    mkdir -p "$REPORTS"
    source venv/bin/activate 2>/dev/null || source venv/Scripts/activate 2>/dev/null || true
    pytest tests/ -v --tb=short | tee "$REPORTS/pytest.txt"
}

run_grype() {
    header "Grype - CVE Scan"
    mkdir -p "$REPORTS"
    require_tool grype "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin" || return
    
    # JSON for visualization scripts
    grype application_2-flask:latest -o json > "$REPORTS/grype-flask.json" 2>/dev/null || true
    grype application_2-nginx:latest -o json > "$REPORTS/grype-nginx.json" 2>/dev/null || true
    
    # Table format for human-readable output
    grype application_2-flask:latest -o table > "$REPORTS/grype-flask.txt" 2>/dev/null || true
    grype application_2-nginx:latest -o table > "$REPORTS/grype-nginx.txt" 2>/dev/null || true
    
    log_success "Grype scans complete (JSON + TXT)"
}

run_trivy() {
    header "Trivy"
    mkdir -p "$REPORTS"
    require_tool trivy "sudo apt install trivy" || return
    trivy image application_2-flask:latest > "$REPORTS/trivy-flask.txt" 2>/dev/null || true
}

run_nmap() {
    header "Nmap - TLS Scan"
    mkdir -p "$REPORTS"
    require_tool nmap "sudo apt install nmap" || return
    nmap -sV -p 80,443,5000 localhost > "$REPORTS/nmap-ports.txt"
    nmap --script ssl-enum-ciphers -p 443 localhost > "$REPORTS/nmap-tls.txt"
}

run_testssl() {
    header "testssl.sh"
    mkdir -p "$REPORTS"
    [ -d "/opt/testssl.sh" ] || { log_warn "testssl.sh not at /opt/testssl.sh"; return; }
    /opt/testssl.sh/testssl.sh --htmlfile "$REPORTS/testssl.html" https://localhost || true
}

run_nikto() {
    header "Nikto"
    mkdir -p "$REPORTS"
    require_tool nikto "sudo apt install nikto" || return
    nikto -h https://localhost -ssl -o "$REPORTS/nikto.html" -Format htm || true
}

run_bandit() {
    header "Bandit"
    mkdir -p "$REPORTS"
    source venv/bin/activate 2>/dev/null || source venv/Scripts/activate 2>/dev/null || true
    bandit -r flask_app.py -f html -o "$REPORTS/bandit.html" || true
}

run_dive() {
    header "Dive"
    mkdir -p "$REPORTS"
    require_tool dive "wget https://github.com/wagoodman/dive/releases/download/v0.12.0/dive_0.12.0_linux_amd64.deb && sudo dpkg -i dive_*.deb" || return
    dive application_2-flask:latest > "$REPORTS/dive.txt" 2>&1 || true
}

run_searchsploit() {
    header "Searchsploit"
    mkdir -p "$REPORTS"
    require_tool searchsploit "sudo apt install exploitdb" || return
    { echo "=== Flask/Gunicorn ==="; searchsploit gunicorn flask 2>/dev/null || echo "None"; echo; echo "=== Nginx ==="; searchsploit nginx 2>/dev/null | head -20; } > "$REPORTS/searchsploit.txt"
}

summary() {
    header "Summary"
    cat > "$REPORTS/SUMMARY.md" <<EOF
# Security Scan Summary - $(date -Iseconds)

| Scan | Status |
|------|--------|
| Pytest | $([ -f "$REPORTS/pytest.txt" ] && echo "✅" || echo "❌") |
| Grype | $([ -f "$REPORTS/grype-flask.json" ] && echo "✅" || echo "❌") |
| Trivy | $([ -f "$REPORTS/trivy-flask.txt" ] && echo "✅" || echo "❌") |
| Nmap | $([ -f "$REPORTS/nmap-ports.txt" ] && echo "✅" || echo "❌") |
| testssl | $([ -f "$REPORTS/testssl.html" ] && echo "✅" || echo "❌") |
| Nikto | $([ -f "$REPORTS/nikto.html" ] && echo "✅" || echo "❌") |
| Bandit | $([ -f "$REPORTS/bandit.html" ] && echo "✅" || echo "❌") |
| Dive | $([ -f "$REPORTS/dive.txt" ] && echo "✅" || echo "❌") |
EOF
    cat "$REPORTS/SUMMARY.md"
}

case "$1" in
    --quick)  check_app; run_pytest; run_nmap; run_bandit; summary ;;
    --help|-h) echo "Usage: $0 [--quick|--help]" ;;
    "")       check_app; run_pytest; run_grype; run_trivy; run_nmap; run_testssl; run_nikto; run_bandit; run_dive; run_searchsploit; summary ;;
    *)        echo "Unknown: $1"; exit 1 ;;
esac