#!/bin/bash
# Setup: install deps, generate secrets/certs/keys, deploy
# Usage: ./setup.sh | ./setup.sh --clean | ./setup.sh --clean-hard

set -eo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }
header()      { echo -e "\n${BLUE}════════════════════════════════════════════════════════════════${NC}\n${BLUE}  $1${NC}\n${BLUE}════════════════════════════════════════════════════════════════${NC}"; }

install_docker() {
    header "Checking Docker"
    if command -v docker &> /dev/null && docker info &> /dev/null; then
        log_success "Docker installed and running"
        return 0
    fi
    log_info "Installing Docker..."
    sudo apt update && sudo apt install -y docker.io docker-compose
    sudo systemctl enable docker --now
    sudo usermod -aG docker $USER
    log_success "Docker installed"
}

install_python_deps() {
    header "Python Environment"
    if [ ! -d "venv" ]; then
        python3 -m venv venv
    fi
    # Linux or Windows venv activation
    if [ -f "venv/bin/activate" ]; then
        source venv/bin/activate
    elif [ -f "venv/Scripts/activate" ]; then
        source venv/Scripts/activate
    fi
    pip install --quiet -r requirements-dev.txt
    log_success "Python ready"
}

generate_secrets() {
    header "Generating Secrets"
    if [ ! -f ".env" ]; then
        cat > .env <<EOF
FLASK_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
KEY_PASSPHRASE=$(python3 -c "import secrets; print(secrets.token_hex(24))")
ADMIN_PASSWORD=$(python3 -c "import secrets; print(secrets.token_hex(16))")
EOF
        chmod 600 .env
        log_success "Secrets generated"
        log_info "Admin password saved to .env"
    else
        log_warn ".env exists, skipping"
    fi
}

generate_certs() {
    header "TLS Certificates"
    mkdir -p certs
    if [ ! -f "certs/nginx.crt" ]; then
        openssl req -x509 -nodes -days 365 -newkey rsa:3072 \
            -keyout certs/nginx.key -out certs/nginx.crt \
            -subj "/C=GB/ST=Bristol/L=Bristol/O=UWE/CN=localhost" \
            -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
            -addext "keyUsage=digitalSignature,keyEncipherment" \
            -addext "extendedKeyUsage=serverAuth" \
            -addext "basicConstraints=critical,CA:FALSE"
        chmod 600 certs/nginx.key
        log_success "Certs generated"
    else
        log_warn "Certs exist, skipping"
    fi
}

generate_keys() {
    header "RSA Signing Keys"
    mkdir -p keys
    if [ ! -f "keys/private_key.pem" ]; then
        [ -f ".env" ] && source .env || { log_error ".env not found"; exit 1; }
        
        openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
            -aes256 -pass "pass:$KEY_PASSPHRASE" -out keys/private_key.pem
        openssl rsa -in keys/private_key.pem -pubout \
            -passin "pass:$KEY_PASSPHRASE" -out keys/public_key.pem
        
        # Container runs as appuser (uid 1000) - must be able to read keys
        chown -R 1000:1000 keys/
        chmod 600 keys/private_key.pem
        chmod 644 keys/public_key.pem
        log_success "RSA-3072 keys generated (encrypted)"
    else
        log_warn "Keys exist, skipping"
    fi
}

deploy_app() {
    header "Deploying"
    [ -f ".env" ] && { set -a; source .env; set +a; } || { log_error ".env not found"; exit 1; }
    
    docker-compose down --volumes --remove-orphans 2>/dev/null || true
    docker-compose up -d --build
    
    log_info "Waiting for startup..."
    sleep 10
    
    if curl -sk https://localhost/health | grep -q "healthy"; then
        log_success "Deployed! Access: https://localhost"
    else
        log_error "Health check failed"
        docker-compose logs
        exit 1
    fi
}

clean_all() {
    header "Cleanup"
    docker-compose down --volumes --remove-orphans 2>/dev/null || true
    rm -rf security-reports/ logs/ __pycache__/ .pytest_cache/ *.sig
    [ "$1" == "--hard" ] && { log_warn "Removing keys, certs, .env"; rm -rf keys/ certs/ .env venv/; }
    log_success "Done"
}

case "$1" in
    --clean)      clean_all ;;
    --clean-hard) clean_all --hard ;;
    --help|-h)    echo "Usage: $0 [--clean|--clean-hard|--help]" ;;
    "")           install_docker; install_python_deps; generate_secrets; generate_certs; generate_keys; deploy_app ;;
    *)            log_error "Unknown: $1"; exit 1 ;;
esac
