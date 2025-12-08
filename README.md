# Secure File Signer

> A STIG-compliant digital signature service using RSA-3072 with PSS padding

---

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Architecture](#architecture)
4. [Original vs Secure Implementation](#original-vs-secure-implementation)
5. [Component Breakdown](#component-breakdown)
   - [Flask Application](#flask-application-flask_apppy)
   - [Nginx Configuration](#nginx-configuration-nginxconf)
   - [Docker Configuration](#docker-configuration)
   - [Automation Scripts](#automation-scripts)
6. [STIG Compliance Matrix](#stig-compliance-matrix)
7. [Security Features Detail](#security-features-detail)
8. [API Reference](#api-reference)
9. [Test Suite](#test-suite)
10. [Security Scan Results](#security-scan-results)
11. [Course Module Integration](#course-module-integration)
12. [Prerequisites & Dependencies](#prerequisites--dependencies)
13. [File Structure](#file-structure)
14. [Troubleshooting & Common Pitfalls](#troubleshooting--common-pitfalls)
15. [Future Improvements](#future-improvements)
16. [FAQ](#faq)
17. [Author](#author)

---

## Overview

### What This Application Does

The **Secure File Signer** is a web-based digital signature service that allows users to:

1. **Sign files** - Upload a document and receive a cryptographic signature (`.sig` file)
2. **Verify signatures** - Upload a document and its signature to verify authenticity

### Purpose

This project was developed for the UWE Cyber Security Engineering module to demonstrate:

- **Secure cryptographic implementations** (RSA-3072, SHA-256, PSS padding)
- **STIG compliance** for web server security (17 controls implemented)
- **Container security hardening** (Docker with read-only filesystems, network isolation)
- **Defense-in-depth architecture** (Nginx reverse proxy + Flask backend)

### How It Fits Into the Larger Project

```
┌──────────────────────────────────────────────────────────────────────────┐
│                           Course Modules                                  │
├──────────────────────────────────────────────────────────────────────────┤
│  Module 1: IaC/Ansible  →  setup.sh automation equivalent                │
│  Module 2: Authentication →  Password auth + account lockout             │
│  Module 3: CI/CD        →  security_test.sh scanning suite               │
│  Module 5: STIGs        →  17 controls implemented                       │
│  Module 6: Security Tools → Grype, Trivy, Nmap, Bandit, Nikto integrated │
│  Module 7: CVE Mgmt     →  Container vulnerability scanning              │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Prerequisites

- **Kali Linux** (recommended) or any Debian-based system
- **Docker** and **Docker Compose** (installed automatically by `setup.sh`)
- **Python 3.9+** with `pip` and `venv`
- **OpenSSL** for certificate/key generation

### Deployment

```bash
# Clone and navigate to the project
cd Application_2

# Full setup: installs dependencies, generates secrets/certs/keys, deploys
./setup.sh

# Access the application
open https://localhost
# Login with password from .env file: cat .env | grep ADMIN_PASSWORD
```

### Security Testing

```bash
# Run full security scan suite (10+ tools)
./security_test.sh

# Quick scan (Pytest + Nmap + Bandit only)
./security_test.sh --quick

# View reports
ls security-reports/
```

### Cleanup

```bash
# Stop containers and remove build artifacts
./setup.sh --clean

# Full reset including keys, certs, and secrets
./setup.sh --clean-hard
```

---

## Architecture

```
┌─────────────┐    HTTPS    ┌─────────────┐    HTTP    ┌─────────────┐
│   Browser   │ ──────────► │    Nginx    │ ─────────► │    Flask    │
│   (User)    │    :443     │   (proxy)   │   :5000    │    (app)    │
└─────────────┘             └─────────────┘            └─────────────┘
                                   │
                            ┌──────┴──────┐
                            │  Security   │
                            │  Controls   │
                            ├─────────────┤
                            │ TLS 1.2/1.3 │
                            │ HSTS Header │
                            │ CSP Headers │
                            │ Rate Limits │
                            └─────────────┘
```

### Component Responsibilities

| Component | Purpose | Key Files |
|-----------|---------|-----------|
| **Flask** | RSA-3072/PSS signing, verification, authentication, logging | `flask_app.py` |
| **Nginx** | TLS termination, security headers, reverse proxy, rate limiting | `nginx.conf` |
| **Docker Compose** | Container orchestration with network isolation | `docker-compose.yml` |
| **Setup Scripts** | Automated deployment and security testing | `setup.sh`, `security_test.sh` |

### Network Isolation

```yaml
networks:
  internal:    # Flask container (isolated from internet)
    internal: true
  external:    # Nginx only (faces the internet)
    driver: bridge
```

- **Flask** can only communicate with Nginx (no direct internet access)
- **Nginx** is the only container exposed to external networks
- All inter-container traffic is isolated on a bridge network

---

## Original vs Secure Implementation

The original `flask_app.py` (107 lines) contained **9 critical security vulnerabilities**. This implementation addresses all of them:

| # | Original Vulnerability | Risk Level | Secure Implementation |
|---|------------------------|------------|----------------------|
| 1 | `dsa.generate_private_key(key_size=1024)` | **Critical** | RSA-3072 with PSS padding |
| 2 | `hashes.SHA1()` | **High** | SHA-256 |
| 3 | `serialization.NoEncryption()` | **High** | AES-256 encrypted private key |
| 4 | `app.logger.info(f'...key {pem_key}')` | **Critical** | Key material never logged |
| 5 | No CSRF protection | **High** | Flask-WTF `CSRFProtect` |
| 6 | No rate limiting | **Medium** | Flask-Limiter (per-endpoint) |
| 7 | `debug=True` | **High** | Gunicorn WSGI server |
| 8 | No input validation | **Medium** | Extension + MIME whitelist |
| 9 | `#TODO` verify endpoint | **Medium** | Full `/verify` + `/api/verify` |

### Before/After Comparison

```python
# BEFORE: Weak cryptography
dsa.generate_private_key(key_size=1024)
hashes.SHA1()

# AFTER: Strong cryptography (V-222542, V-222543)
# RSA-3072 keys with PSS padding and SHA-256
PSS_PADDING = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH
)
```

---

## Component Breakdown

### Flask Application (`flask_app.py`)

**Lines of Code:** 559  
**Purpose:** Core application logic for signing, verification, and authentication

#### Key Classes and Functions

| Component | Lines | Purpose |
|-----------|-------|---------|
| `Config` | 35-53 | Immutable dataclass for application settings |
| `LoginAttemptTracker` | 121-158 | Account lockout with exponential backoff |
| `STIGFormatter` | 165-176 | STIG-compliant log formatting |
| `setup_logging()` | 178-203 | Rotating file + stream logging setup |
| `validate_file_upload()` | 302-321 | Extension + MIME type validation |
| `load_private_key()` | 242-244 | Encrypted key loading |
| `hash_file_contents()` | 281-288 | Chunked file hashing for large files |

#### Route Handlers

| Route | Method | Auth Required | Rate Limit | Purpose |
|-------|--------|---------------|------------|---------|
| `/` | GET | No | Default | Home page |
| `/login` | GET/POST | No | 10/min | Authentication |
| `/logout` | GET | Yes | Default | Clear session |
| `/sign` | GET/POST | Yes | 5/min | Sign uploaded files |
| `/verify` | GET/POST | Yes | 10/min | Verify signatures (HTML) |
| `/api/verify` | POST | Yes | 20/min | Verify signatures (JSON API) |
| `/health` | GET | No | Default | Container health check |

#### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `FLASK_SECRET_KEY` | ✅ | Session encryption key (32 hex chars) |
| `ADMIN_PASSWORD` | ✅ | Login password (auto-generated) |
| `KEY_PASSPHRASE` | Optional | Private key encryption passphrase |
| `PRIVATE_KEY_PATH` | Optional | Path to RSA private key |
| `PUBLIC_KEY_PATH` | Optional | Path to RSA public key |
| `LOG_DIR` | Optional | Log directory (default: `/app/logs`) |
| `BEHIND_PROXY` | Optional | Enable X-Forwarded-* header parsing |
| `TESTING` | Optional | Enable test mode (relaxes key validation) |

---

### Nginx Configuration (`nginx.conf`)

**Lines of Code:** 107  
**Purpose:** TLS termination, security headers, reverse proxy

#### TLS Configuration (NIST 800-52 Compliant)

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:
            ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:
            ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers off;
ssl_session_tickets off;
```

#### Security Headers

| Header | Value | Purpose |
|--------|-------|---------|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` | Force HTTPS for 1 year |
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'...` | Prevent XSS/injection |
| `X-Frame-Options` | `DENY` | Prevent clickjacking |
| `X-Content-Type-Options` | `nosniff` | Prevent MIME sniffing |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Control referrer leakage |
| `Permissions-Policy` | `camera=(), microphone=()...` | Disable dangerous APIs |
| `Cross-Origin-*` | Various | CORS protection |

#### Rate Limiting Zones

```nginx
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=general_limit:10m rate=30r/s;
limit_conn_zone $binary_remote_addr zone=conn_limit:10m;
```

---

### Docker Configuration

#### Flask Container (`flask_dockerfile`)

**Base Image:** `majidockerid/uwe:application2` (Debian-based Python)

**Security Hardening:**
- Non-root execution (`USER appuser`, UID 1000)
- Build dependencies removed after install (`gcc` purged)
- Gunicorn WSGI server (no Flask debug mode)
- Health check endpoint (`/health`)
- Worker process limits and request jitter

```dockerfile
# V-222430: Non-root execution
USER appuser

CMD ["gunicorn", "--workers", "4", "--bind", "0.0.0.0:5000", 
     "--max-requests", "1000", "--max-requests-jitter", "50", "app:app"]
```

#### Nginx Container (`nginx_dockerfile`)

**Base Image:** `nginx:1.27-alpine` (minimal attack surface)

**Security Hardening:**
- Alpine Linux (smaller attack surface)
- Security updates applied at build time
- Certificates mounted at runtime (not baked into image)
- Health check with SSL verification disabled (self-signed cert)

#### Docker Compose (`docker-compose.yml`)

**Security Controls:**

```yaml
services:
  flask:
    security_opt:
      - no-new-privileges:true    # Prevent privilege escalation
    read_only: true               # Immutable filesystem
    tmpfs:
      - /tmp:mode=1777,size=64M   # Ephemeral writable space
    deploy:
      resources:
        limits:
          cpus: '0.50'
          memory: 512M            # Resource exhaustion protection
```

---

### Automation Scripts

#### `setup.sh` - Deployment Automation

**Usage:**
```bash
./setup.sh           # Full deployment
./setup.sh --clean   # Stop and clean build artifacts
./setup.sh --clean-hard  # Full reset including secrets
```

**What It Does:**
1. Checks/installs Docker and Docker Compose
2. Creates Python virtual environment with dependencies
3. Generates cryptographic secrets (hex tokens)
4. Generates self-signed TLS certificates (RSA-3072)
5. Generates encrypted RSA-3072 signing keys
6. Deploys containers with health check verification

**Secret Generation:**
```bash
FLASK_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
KEY_PASSPHRASE=$(python3 -c "import secrets; print(secrets.token_hex(24))")
ADMIN_PASSWORD=$(python3 -c "import secrets; print(secrets.token_hex(16))")
```

#### `security_test.sh` - Security Scanning

**Usage:**
```bash
./security_test.sh        # Full scan (all tools)
./security_test.sh --quick  # Quick scan (Pytest, Nmap, Bandit)
```

**Integrated Tools:**

| Tool | Purpose | Output |
|------|---------|--------|
| **Pytest** | Unit + security tests | `pytest.txt` |
| **Grype** | Container CVE scanning | `grype-flask.json`, `grype-flask.txt` |
| **Trivy** | Image vulnerabilities | `trivy-flask.txt` |
| **Nmap** | Port + TLS cipher enumeration | `nmap-ports.txt`, `nmap-tls.txt` |
| **testssl.sh** | TLS configuration audit | `testssl.html` |
| **Nikto** | Web vulnerability scan | `nikto.html` |
| **Bandit** | Python static analysis | `bandit.html` |
| **Dive** | Image layer analysis | `dive.txt` |
| **Searchsploit** | Known exploit database | `searchsploit.txt` |

---

## STIG Compliance Matrix

### Implemented Controls (17)

| STIG ID | Control | Implementation | Location |
|---------|---------|----------------|----------|
| **V-222542** | FIPS-Approved Algorithms | RSA-3072 + SHA-256 + PSS | `flask_app.py:57-60` |
| **V-222543** | Key Length ≥3072 | Runtime validation | `flask_app.py:252-273` |
| **V-222596** | Private Key Protection | AES-256 encrypted via `KEY_PASSPHRASE` | `flask_app.py:62-65` |
| **V-222602** | CSRF Protection | Flask-WTF on all forms | `flask_app.py:94` |
| **V-222603** | Input Validation | Extension + MIME type checking | `flask_app.py:291-321` |
| **V-222604** | Timing-Safe Comparison | `secrets.compare_digest()` | `flask_app.py:365` |
| **V-222607** | Account Lockout | `LoginAttemptTracker` with exponential backoff | `flask_app.py:121-158` |
| **V-222609** | Rate Limiting | Flask-Limiter: 5/min sign, 10/min verify | `flask_app.py:95-100` |
| **V-222574** | Secure Cookies | `Secure`, `HttpOnly`, `SameSite=Lax`, `__Host-` prefix | `flask_app.py:82-86` |
| **V-222579** | Session Management | 1-hour timeout, no remember | `flask_app.py:86` |
| **V-222610** | Log Timestamp | ISO 8601 format | `flask_app.py:183` |
| **V-222613** | User Authentication | Flask-Login + password | `flask_app.py:103-118` |
| **V-222614** | Log Client IP | `IP:%(client_ip)s` in log format | `flask_app.py:182` |
| **V-222615** | Log Request ID | UUID tracking per request | `flask_app.py:214-227` |
| **V-206439** | TLS 1.2/1.3 Only | `ssl_protocols TLSv1.2 TLSv1.3` | `nginx.conf:58` |
| **V-222598** | HSTS Header | `max-age=31536000; includeSubDomains` | `nginx.conf:67` |
| **V-222430** | Non-Root Execution | `USER appuser` in Dockerfile | `flask_dockerfile:26` |

### Not Applicable Controls (Justified)

| Control | Justification |
|---------|---------------|
| CA-signed certificates | Development environment - self-signed per course guidance |
| Multi-factor authentication | Single-admin signing service - password + lockout sufficient |
| OCSP Stapling | Self-signed certificates don't use OCSP |

---

## Security Features Detail

### 1. Authentication & Account Lockout (V-222607)

```python
class LoginAttemptTracker:
    """Track failed logins with exponential backoff lockout."""
    
    MAX_ATTEMPTS = 5
    LOCKOUT_MULTIPLIER = 60  # Base: 60 seconds
    
    def record_failure(self, ip: str) -> None:
        # Expire attempts older than 15 minutes
        self._attempts[ip] = [t for t in self._attempts[ip] 
                              if (now - t).total_seconds() < 900]
        
        if len(self._attempts[ip]) >= self.MAX_ATTEMPTS:
            lockout_count = len(self._attempts[ip]) - self.MAX_ATTEMPTS + 1
            # Exponential: 60s → 120s → 240s → 480s → 960s (max)
            lockout_seconds = self.LOCKOUT_MULTIPLIER * (2 ** min(lockout_count - 1, 4))
            self._lockouts[ip] = now + timedelta(seconds=lockout_seconds)
```

**Behavior:**
- 5 failed attempts within 15 minutes triggers lockout
- Lockout duration doubles each time: 1min → 2min → 4min → 8min → 16min (max)
- Successful login clears all attempt history

### 2. Timing-Safe Password Comparison (V-222604)

```python
# Prevents timing attacks by ensuring constant-time comparison
if admin_password and secrets.compare_digest(password, admin_password):
    login_user(User('admin'), remember=False)
```

**Why This Matters:**
- String comparison (`==`) short-circuits on first mismatch
- Attackers can measure response time to guess password character-by-character
- `secrets.compare_digest()` takes constant time regardless of where mismatch occurs

### 3. Input Validation (V-222603)

```python
ALLOWED_MIMETYPES = {
    'txt': {'text/plain'},
    'pdf': {'application/pdf'},
    'doc': {'application/msword'},
    'docx': {'application/vnd.openxmlformats-officedocument.wordprocessingml.document'},
    'png': {'image/png'},
    'jpg': {'image/jpeg'},
}

def validate_file_upload(request_files, field_name='file', check_extension=True):
    ext = file.filename.rsplit('.', 1)[1].lower()
    # Extension must match Content-Type header
    if ext in ALLOWED_MIMETYPES and file.content_type not in ALLOWED_MIMETYPES[ext]:
        logger.warning(f"MIME mismatch: ext={ext}, type={file.content_type}")
        return None, 'File type mismatch'
```

**Double Validation:**
1. File extension must be in whitelist
2. Content-Type header must match expected MIME type for extension

### 4. Open Redirect Prevention (V-222609)

```python
# Only allow relative URLs after login
next_page = request.args.get('next', '')
if next_page and urlparse(next_page).netloc == '':  # No domain = relative
    return redirect(next_page)
return redirect(url_for('index'))  # Default to safe page
```

**Why This Matters:**
- Attackers craft URLs like `/login?next=https://evil.com`
- After login, user is redirected to attacker's phishing site
- This check rejects any URL with a domain (absolute URLs)

### 5. STIG-Compliant Logging (V-222610, V-222614, V-222615)

```python
class STIGFormatter(logging.Formatter):
    """Log format: timestamp | level | request_id | client_ip | user | message"""
    
formatter = STIGFormatter(
    fmt='%(asctime)s | %(levelname)-8s | REQ:%(request_id)s | IP:%(client_ip)s | USER:%(user_id)s | %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S%z'
)
```

**Sample Output:**
```
2025-12-07T12:54:32+0000 | INFO     | REQ:a1b2c3d4 | IP:192.168.1.100 | USER:admin | AUDIT: FILE_SIGN - STARTED
```

---

## API Reference

### Endpoints Overview

| Endpoint | Method | Auth | Rate Limit | Description |
|----------|--------|------|------------|-------------|
| `/` | GET | No | 200/day | Home page with navigation |
| `/login` | GET | No | 10/min | Login form |
| `/login` | POST | No | 10/min | Authenticate with password |
| `/logout` | GET | Yes | 200/day | Clear session and redirect |
| `/sign` | GET | Yes | 5/min | File upload form |
| `/sign` | POST | Yes | 5/min | Sign file and return `.sig` |
| `/verify` | GET | Yes | 10/min | Verification form |
| `/verify` | POST | Yes | 10/min | Verify signature (HTML response) |
| `/api/verify` | POST | Yes | 20/min | Verify signature (JSON response) |
| `/health` | GET | No | 200/day | Container health status |

### API Verify (JSON Endpoint)

**Request:**
```bash
curl -X POST https://localhost/api/verify \
  -F "file=@document.pdf" \
  -F "signature=@document.pdf.sig" \
  -H "Cookie: __Host-session=<session_cookie>" \
  --insecure  # Only for self-signed certs
```

**Success Response (200):**
```json
{
  "valid": true,
  "filename": "document.pdf",
  "bytes": 12345
}
```

**Failure Responses:**

| Status | Response | Cause |
|--------|----------|-------|
| 400 | `{"valid": false, "error": "Missing file or signature"}` | Missing form fields |
| 400 | `{"valid": false, "error": "Empty filename"}` | No file selected |
| 400 | `{"valid": false, "error": "Signature too large"}` | Signature > 1KB |
| 200 | `{"valid": false, "error": "Invalid signature"}` | Verification failed |
| 500 | `{"valid": false, "error": "Verification failed"}` | Internal error |

### Authentication Flow

```
1. User visits /sign (protected route)
2. Flask-Login redirects to /login?next=/sign
3. User submits password
4. If valid: session cookie set, redirect to /sign
5. If invalid: failure recorded, error message shown
6. After 5 failures: account locked with exponential backoff
```

---

## Test Suite

### Test Structure

```
tests/
├── __init__.py       # Package marker
├── conftest.py       # Pytest fixtures (77 lines)
├── run_all_tests.py  # Consolidated test runner
└── test_unit.py      # Unit + security tests (94 lines)
```

### Running Tests

```bash
# Activate virtual environment
source venv/bin/activate  # Linux/Mac
source venv/Scripts/activate  # Windows

# Run all tests with verbose output
pytest tests/ -v

# Run with coverage report
pytest tests/ -v --cov=flask_app --cov-report=html

# Run specific test class
pytest tests/test_unit.py::TestSigningWorks -v
```

### Test Categories

| Test Class | Tests | What It Verifies |
|------------|-------|------------------|
| `TestSigningWorks` | 2 | File signing, blocked extensions |
| `TestVerificationWorks` | 2 | Valid signatures, tampered file detection |
| `TestCryptoCorrect` | 1 | PSS probabilistic padding (same file → different sigs) |
| `TestRateLimiting` | 1 | Flask-Limiter triggers at 429 |
| `TestCSRFProtection` | 1 | POST without token returns 400 |
| `TestLogFormat` | 1 | Logging runs without error |
| `TestHealthCheck` | 1 | Health endpoint returns JSON |
| `TestAuthentication` | 1 | Protected routes redirect to login |

### Latest Test Results

```
tests/test_unit.py::TestSigningWorks::test_can_sign_file PASSED
tests/test_unit.py::TestSigningWorks::test_exe_files_blocked PASSED
tests/test_unit.py::TestVerificationWorks::test_valid_signature_verifies PASSED
tests/test_unit.py::TestVerificationWorks::test_tampered_file_fails PASSED
tests/test_unit.py::TestCryptoCorrect::test_pss_padding_is_probabilistic PASSED
tests/test_unit.py::TestRateLimiting::test_sign_rate_limit_triggers PASSED
tests/test_unit.py::TestCSRFProtection::test_post_without_csrf_rejected PASSED
tests/test_unit.py::TestLogFormat::test_logging_works PASSED
tests/test_unit.py::TestHealthCheck::test_health_returns_json PASSED
tests/test_unit.py::TestAuthentication::test_sign_requires_login PASSED

============================== 10 passed in 2.78s ==============================
```

---

## Security Scan Results

### Summary Table

| Tool | Status | Critical/High Issues | Notes |
|------|--------|---------------------|-------|
| **Pytest** | ✅ 10/10 passed | 0 | All tests pass |
| **Bandit** | ✅ Clean | 0 | No issues in flask_app.py |
| **Nmap TLS** | ✅ Grade A | 0 | TLS 1.2/1.3 only, strong ciphers |
| **Grype (Flask)** | ⚠️ Findings | See below | Base image CVEs |
| **Grype (Nginx)** | ✅ Minimal | 1 Low | Alpine base minimal issues |
| **Trivy** | ⚠️ Findings | See below | OS package CVEs |
| **Nikto** | ✅ Expected | Info only | Self-signed cert warnings |
| **testssl.sh** | ✅ Pass | 0 | NIST 800-52 compliant |

### Nmap TLS Cipher Scan

```
PORT    STATE SERVICE
443/tcp open  https
| ssl-enum-ciphers: 
|   TLSv1.2: 
|     ciphers: 
|       TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (secp256r1) - A
|       TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (secp256r1) - A
|       TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (secp256r1) - A
|   TLSv1.3: 
|       TLS_AKE_WITH_AES_128_GCM_SHA256 (ecdh_x25519) - A
|       TLS_AKE_WITH_AES_256_GCM_SHA384 (ecdh_x25519) - A
|       TLS_AKE_WITH_CHACHA20_POLY1305_SHA256 (ecdh_x25519) - A
|_  least strength: A
```

**Result:** All ciphers graded **A**. No weak ciphers detected.

### Grype CVE Analysis (Flask Container)

| Severity | Count | Action |
|----------|-------|--------|
| Critical | 2 | Base image OS packages - monitored |
| High | 12 | Python version + OS packages |
| Medium | 18 | Low EPSS scores (<0.1%) |
| Low | 5 | Informational |
| Negligible | 49 | No action required |

**Key Findings:**
- Most HIGH/CRITICAL are in base OS packages (`libldap`, `python`, `libpam`)
- Marked as `(won't fix)` by Debian maintainers
- Low EPSS (Exploit Prediction Scoring System) scores indicate low real-world risk
- **Mitigation:** Regular `apt-get upgrade` in Dockerfile (implemented)

### Understanding the Vulnerability Findings

> **Important:** Many CVEs flagged in container scans are:
> 1. **OS-level packages** we don't directly use
> 2. **Won't Fix** status from Debian maintainers (disputed or theoretical)
> 3. **Low EPSS scores** indicating no known active exploitation
> 
> The application code itself (flask_app.py) passes Bandit static analysis with no issues.

---

## Course Module Integration

### Module Mapping

| Module | Topic | Implementation | Status |
|--------|-------|----------------|--------|
| **Module 1** | Ansible/IaC | `setup.sh` provides equivalent automation | ✅ |
| **Module 2** | Auth/JWT/MFA | Password auth + lockout | ✅ |
| **Module 3** | CI/CD (Jenkins) | `security_test.sh` (manual trigger) | ✅ |
| **Module 5** | STIGs | 17 controls implemented | ✅ |
| **Module 6** | Security Tools | 9 tools integrated | ✅ |
| **Module 7** | CVE Management | Grype/Trivy container scanning | ✅ |

### Design Decisions

#### Why `setup.sh` Instead of Ansible?

| Ansible | `setup.sh` |
|---------|-----------|
| Requires Python + Ansible installation | Bash only (built-in) |
| Complex YAML playbooks | Linear shell script |
| Designed for multi-machine orchestration | Single-machine deployment |
| **Conclusion:** Ansible adds complexity without benefit for this scope |

The `setup.sh` script achieves equivalent automation:
- Dependency installation
- Secret generation
- Certificate/key creation
- Container deployment
- Health verification

#### Why Password Auth Instead of JWT/MFA?

| Requirement | Implementation |
|-------------|----------------|
| V-222613 requires user identity | ✅ Flask-Login provides user tracking |
| Single-admin signing service | Password auth is appropriate |
| MFA adds UX complexity | Not required for project scope |
| Brute-force protection | ✅ Account lockout with exponential backoff |

---

## Prerequisites & Dependencies

### System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| OS | Debian 11+ / Ubuntu 22.04+ | Kali Linux |
| CPU | 1 core | 2 cores |
| RAM | 1 GB | 2 GB |
| Disk | 2 GB | 5 GB |
| Python | 3.9 | 3.11+ |
| Docker | 20.10+ | 24.0+ |

### Python Dependencies (`requirements.txt`)

| Package | Version | Purpose |
|---------|---------|---------|
| `Flask` | ≥3.0.0 | Web framework |
| `cryptography` | ≥43.0.1 | RSA/SHA-256 operations |
| `Flask-WTF` | ≥1.2.0 | CSRF protection |
| `Flask-Limiter` | ≥3.5.0 | Rate limiting |
| `Flask-Login` | ≥0.6.3 | Authentication |
| `gunicorn` | ≥21.0.0 | Production WSGI server |
| `werkzeug` | ≥3.0.6 | Request handling |

### Development Dependencies (`requirements-dev.txt`)

| Package | Purpose |
|---------|---------|
| `pytest` | Test framework |
| `pytest-flask` | Flask test fixtures |
| `pytest-cov` | Coverage reporting |
| `bandit` | Security linting |
| `black` | Code formatting |
| `mypy` | Type checking |

### Security Tool Requirements

Install on Kali Linux (most are pre-installed):

```bash
# Container scanning
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin
sudo apt install trivy

# Web scanning
sudo apt install nmap nikto

# TLS testing
git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh

# Image analysis
wget https://github.com/wagoodman/dive/releases/download/v0.12.0/dive_0.12.0_linux_amd64.deb
sudo dpkg -i dive_*.deb
```

---

## File Structure

```
Application_2/
├── setup.sh                    # Deployment automation
├── security_test.sh            # Security scan runner
│
├── flask_app.py                # Flask application (559 lines)
├── flask_dockerfile            # Flask container build (41 lines)
├── nginx_dockerfile            # Nginx container build (15 lines)
├── nginx.conf                  # Nginx configuration (107 lines)
├── docker-compose.yml          # Container orchestration (102 lines)
│
├── requirements.txt            # Production dependencies
├── requirements-dev.txt        # Development dependencies
│
├── tests/                      # Test suite
│   ├── __init__.py
│   ├── conftest.py             # Pytest fixtures
│   ├── run_all_tests.py        # Test runner
│   └── test_unit.py            # Unit + security tests
│
├── templates/                  # Jinja2 HTML templates
│   ├── index.html              # Home page
│   ├── login.html              # Login form
│   ├── sign.html               # File signing form
│   └── verify.html             # Signature verification form
│
├── static/
│   └── style.css               # CSS styles
│
├── keys/                       # RSA keypair (generated by setup.sh)
│   ├── private_key.pem         # Encrypted private key
│   └── public_key.pem          # Public key
│
├── certs/                      # TLS certificates (generated by setup.sh)
│   ├── nginx.crt               # Self-signed certificate
│   └── nginx.key               # Certificate private key
│
├── security-reports/           # Security scan results
│   ├── pytest.txt
│   ├── grype-flask.json
│   ├── grype-flask.txt
│   ├── nmap-tls.txt
│   └── ...
│
├── .env                        # Secrets (generated, chmod 600)
├── .gitignore                  # Git exclusions
└── .dockerignore               # Docker build exclusions
```

---

## Troubleshooting & Common Pitfalls

### Common Issues

#### 1. "FLASK_SECRET_KEY not set"

**Cause:** `.env` file not found or not sourced  
**Solution:**
```bash
# Regenerate secrets
./setup.sh --clean-hard
./setup.sh
```

#### 2. Container health check fails

**Cause:** Flask app not starting correctly  
**Solution:**
```bash
# Check container logs
docker-compose logs flask

# Common issues:
# - Missing KEY_PASSPHRASE (key decryption fails)
# - Permission issues on keys/ directory
```

#### 3. "Key not found" or key validation fails

**Cause:** Keys not generated or wrong permissions  
**Solution:**
```bash
# Regenerate keys with correct ownership
rm -rf keys/
./setup.sh

# Verify permissions
ls -la keys/
# Should show: private_key.pem owned by 1000:1000, mode 600
```

#### 4. Rate limit triggered during testing

**Cause:** Flask-Limiter active during tests  
**Solution:**
```python
# In conftest.py, limiter is disabled:
limiter.enabled = False

# If still seeing 429 errors, check test isolation
```

#### 5. CSRF token missing in form

**Cause:** Template missing `{{ csrf_token() }}`  
**Solution:** All forms must include the hidden CSRF field:
```html
<form method="POST">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    ...
</form>
```

#### 6. SSL certificate warnings

**Cause:** Self-signed certificate (expected in development)  
**Solution:**
```bash
# Add --insecure for curl
curl -k https://localhost/health

# Or accept the certificate in browser
```

### Pitfalls to Avoid

| Pitfall | Why It's Bad | Correct Approach |
|---------|-------------|------------------|
| Checking `.env` into git | Exposes secrets | `.gitignore` includes `.env` |
| Running without KEY_PASSPHRASE | Private key unencrypted | Always set in production |
| Using `debug=True` in production | Exposes stack traces | Gunicorn handles this |
| Trusting file extensions only | MIME spoofing | Extension + MIME validation |
| Logging key material | Key exposure | Never log private keys |

---

## Future Improvements

### Recommended Enhancements

| Improvement | Benefit | Implementation Approach |
|-------------|---------|------------------------|
| **Docker Secrets** | Secrets not in .env file | Use Docker Swarm or Kubernetes Secrets |
| **HashiCorp Vault** | Dynamic secret management | Vault agent sidecar pattern |
| **Redis session storage** | Multi-instance support | `Flask-Session` with Redis backend |
| **Redis rate limiting** | Shared state across workers | `storage_uri="redis://..."` |
| **OCSP Stapling** | Faster TLS handshakes | `ssl_stapling on` (requires CA cert) |
| **DH Parameters** | Stronger key exchange | `openssl dhparam -out dhparam.pem 3072` |

### Docker Secrets Example (Not Implemented)

```yaml
# How I would implement Docker Secrets in Swarm mode
services:
  flask:
    secrets:
      - flask_secret_key
      - key_passphrase
      - admin_password
    environment:
      - FLASK_SECRET_KEY_FILE=/run/secrets/flask_secret_key

secrets:
  flask_secret_key:
    external: true  # Created via: docker secret create flask_secret_key ./secret.txt
```

**Why Not Implemented:**
- Docker Compose (standalone) doesn't support secrets
- Would require Docker Swarm mode
- `.env` with `chmod 600` is acceptable for development scope
- STIG doesn't mandate specific secret storage mechanism

---

## FAQ

### General Questions

**Q: Is this production-ready?**

A: For the course project scope, yes. For real-world production, you would want:
- CA-signed TLS certificates
- External secret management (Vault, AWS Secrets Manager)
- Redis-backed session/rate-limiting storage
- Load balancer with health checks
- Centralized logging (ELK stack, CloudWatch)

**Q: Why RSA-3072 instead of RSA-4096?**

A: RSA-3072 provides equivalent security to 128-bit AES and is the minimum recommended by NIST for use until 2030. RSA-4096 adds 33% more computational overhead with minimal security benefit for this timeframe.

**Q: Why PSS padding instead of PKCS#1 v1.5?**

A: PSS (Probabilistic Signature Scheme) is:
- Probabilistic: Same message produces different signatures (prevents signature analysis)
- Provably secure: Mathematical proof of security reduction
- FIPS 186-4 recommended for new applications

**Q: Can I use this for documents requiring legal validity?**

A: No. Legal digital signatures typically require:
- Certificate from accredited CA
- Timestamping authority
- eIDAS/ESIGN compliance (depending on jurisdiction)

### Technical Questions

**Q: How do I retrieve the admin password?**

A:
```bash
grep ADMIN_PASSWORD .env
```

**Q: How do I add a new allowed file type?**

A: Edit `flask_app.py`:
```python
ALLOWED_MIMETYPES = {
    'txt': {'text/plain'},
    'pdf': {'application/pdf'},
    'xml': {'application/xml', 'text/xml'},  # Add new type
    # ...
}
```
Also update `Config.ALLOWED_EXTENSIONS`.

**Q: How do I increase the rate limits?**

A: Edit the decorator on each route:
```python
@limiter.limit("20 per minute")  # Increase from 5 to 20
def sign():
```

**Q: How do I view the application logs?**

A:
```bash
# Container logs (stdout)
docker-compose logs -f flask

# Application logs (persisted)
docker exec -it flask-app cat /app/logs/flask_app.log
```

**Q: Why does Grype show so many vulnerabilities?**

A: Grype scans the entire container image, including:
- Base OS packages (Debian/Alpine)
- Python runtime
- System libraries

Most findings are:
- Low EPSS scores (not actively exploited)
- OS packages marked "won't fix" by maintainers
- Not directly used by the application

The application code itself (flask_app.py) passes Bandit with no issues.

**Q: How do I run only specific tests?**

A:
```bash
# Run one test class
pytest tests/test_unit.py::TestSigningWorks -v

# Run one specific test
pytest tests/test_unit.py::TestSigningWorks::test_can_sign_file -v

# Run tests matching a pattern
pytest tests/ -k "signing or verify" -v
```

---

## Author

**L7Dawson**  
December 2025

---

## License

MIT License

ChatGPT 4o generated this README.md file - All licenses to them?
