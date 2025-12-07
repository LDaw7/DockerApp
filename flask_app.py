"""
Secure File Signing Application
RSA-3072/PSS digital signature service with STIG compliance.
Author: L7Dawson
"""

import os
import re
import sys
import uuid
import secrets
import logging
import logging.handlers
import io
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, Tuple, IO, FrozenSet
from datetime import datetime, timezone, timedelta
from functools import wraps
from urllib.parse import urlparse

from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.middleware.proxy_fix import ProxyFix
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.exceptions import InvalidSignature
from flask import Flask, render_template, request, send_file, redirect, url_for, flash, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user


@dataclass(frozen=True)
class Config:
    """Immutable application configuration."""
    MAX_UPLOAD_SIZE: int = 16 * 1024 * 1024
    MAX_SIGNATURE_SIZE: int = 1024
    ALLOWED_EXTENSIONS: FrozenSet[str] = field(
        default_factory=lambda: frozenset({'txt', 'pdf', 'doc', 'docx', 'png', 'jpg'})
    )
    PRIVATE_KEY_PATH: str = field(
        default_factory=lambda: os.environ.get('PRIVATE_KEY_PATH', 'keys/private_key.pem')
    )
    PUBLIC_KEY_PATH: str = field(
        default_factory=lambda: os.environ.get('PUBLIC_KEY_PATH', 'keys/public_key.pem')
    )
    LOG_DIR: str = field(default_factory=lambda: os.environ.get('LOG_DIR', '/app/logs'))
    DEFAULT_RATE_LIMIT: str = "200 per day"
    SIGN_RATE_LIMIT: str = "5 per minute"
    VERIFY_RATE_LIMIT: str = "10 per minute"


config = Config()

PSS_PADDING = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH
)

# V-222596: Key encryption passphrase from environment
KEY_PASSPHRASE: Optional[bytes] = None
if os.environ.get('KEY_PASSPHRASE'):
    KEY_PASSPHRASE = os.environ['KEY_PASSPHRASE'].encode()


# ── Flask Setup ───────────────────────────────────────────────────────────────

app = Flask(__name__)

_secret_key = os.environ.get('FLASK_SECRET_KEY')
if not _secret_key:
    if os.environ.get('TESTING', '').lower() in ('true', '1', 'yes'):
        _secret_key = 'test-secret-key-not-for-production'
    else:
        sys.exit("FLASK_SECRET_KEY not set")
app.secret_key = _secret_key

app.config.update(
    MAX_CONTENT_LENGTH=config.MAX_UPLOAD_SIZE,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_NAME='__Host-session',         # V-222579
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1), # V-222579
    WTF_CSRF_TIME_LIMIT=3600,
)

# Trust X-Forwarded-* headers when behind Nginx
if os.environ.get('BEHIND_PROXY', '').lower() == 'true':
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

csrf = CSRFProtect(app)
limiter = Limiter(
    get_remote_address, 
    app=app, 
    default_limits=[config.DEFAULT_RATE_LIMIT, "50 per hour"], 
    storage_uri="memory://"
)


# ── Authentication (V-222613) ─────────────────────────────────────────────────

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'error'


class User(UserMixin):
    def __init__(self, id: str):
        self.id = id


@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    return User(user_id) if user_id == 'admin' else None


class LoginAttemptTracker:
    """V-222607: Track failed logins with exponential backoff lockout."""
    
    MAX_ATTEMPTS = 5
    LOCKOUT_MULTIPLIER = 60
    
    def __init__(self):
        self._attempts: Dict[str, list] = {}
        self._lockouts: Dict[str, datetime] = {}
    
    def is_locked_out(self, ip: str) -> Tuple[bool, int]:
        if ip in self._lockouts:
            lockout_until = self._lockouts[ip]
            if datetime.now(timezone.utc) < lockout_until:
                return True, int((lockout_until - datetime.now(timezone.utc)).total_seconds())
            del self._lockouts[ip]
        return False, 0
    
    def record_failure(self, ip: str) -> None:
        now = datetime.now(timezone.utc)
        
        # Expire attempts older than 15 minutes
        if ip in self._attempts:
            self._attempts[ip] = [t for t in self._attempts[ip] if (now - t).total_seconds() < 900]
        else:
            self._attempts[ip] = []
        
        self._attempts[ip].append(now)
        
        if len(self._attempts[ip]) >= self.MAX_ATTEMPTS:
            lockout_count = len(self._attempts[ip]) - self.MAX_ATTEMPTS + 1
            lockout_seconds = self.LOCKOUT_MULTIPLIER * (2 ** min(lockout_count - 1, 4))
            self._lockouts[ip] = now + timedelta(seconds=lockout_seconds)
    
    def clear(self, ip: str) -> None:
        self._attempts.pop(ip, None)
        self._lockouts.pop(ip, None)


login_tracker = LoginAttemptTracker()


# ── STIG-Compliant Logging (V-222610–V-222615) ────────────────────────────────

class STIGFormatter(logging.Formatter):
    """Log format: timestamp | level | request_id | client_ip | user | message"""
    
    def format(self, record: logging.LogRecord) -> str:
        try:
            record.request_id = getattr(g, 'request_id', 'SYSTEM')
            record.client_ip = getattr(g, 'client_ip', 'N/A')
            record.user_id = getattr(g, 'user_id', 'anonymous')
        except RuntimeError:
            record.request_id, record.client_ip, record.user_id = 'SYSTEM', 'N/A', 'system'
        return super().format(record)


def setup_logging() -> logging.Logger:
    os.makedirs(config.LOG_DIR, exist_ok=True)
    
    formatter = STIGFormatter(
        fmt='%(asctime)s | %(levelname)-8s | REQ:%(request_id)s | IP:%(client_ip)s | USER:%(user_id)s | %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S%z'
    )
    
    file_handler = logging.handlers.RotatingFileHandler(
        os.path.join(config.LOG_DIR, "flask_app.log"),
        maxBytes=10*1024*1024, backupCount=5, encoding='utf-8'
    )
    file_handler.setFormatter(formatter)
    
    # V-206366: Alert on log failure via stderr
    file_handler.handleError = lambda r: print(f"ALERT: Log write failure", file=sys.stderr)
    
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.addHandler(file_handler)
    root.addHandler(stream_handler)
    
    return logging.getLogger(__name__)


logger = setup_logging()


# ── Request Context ───────────────────────────────────────────────────────────

REQUEST_ID_PATTERN = re.compile(r'^[a-zA-Z0-9\-_]{1,36}$')


@app.before_request
def before_request() -> None:
    # V-222615: Request tracing
    provided_id = request.headers.get('X-Request-ID', '')
    g.request_id = provided_id[:8] if provided_id and REQUEST_ID_PATTERN.match(provided_id) else str(uuid.uuid4())[:8]
    
    # V-222614: Client IP
    g.client_ip = request.remote_addr or 'unknown'
    
    # V-222613: User identity
    g.user_id = current_user.id if current_user.is_authenticated else 'anonymous'
    
    logger.info(f"REQUEST_START: {request.method} {request.path}")


@app.after_request
def after_request(response):
    logger.info(f"REQUEST_END: {request.method} {request.path} -> {response.status_code}")
    response.headers['X-Request-ID'] = g.get('request_id', 'unknown')
    return response


# ── Key Management ────────────────────────────────────────────────────────────

def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in config.ALLOWED_EXTENSIONS


def load_private_key() -> RSAPrivateKey:
    with open(config.PRIVATE_KEY_PATH, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=KEY_PASSPHRASE)


def load_public_key():
    with open(config.PUBLIC_KEY_PATH, 'rb') as f:
        return serialization.load_pem_public_key(f.read())


def verify_keys() -> None:
    """Verify keys exist and meet V-222543 (≥3072 bits)."""
    testing = os.environ.get('TESTING', '').lower() in ('true', '1', 'yes')
    
    def check(condition: bool, msg: str):
        if condition:
            return
        if testing:
            logger.warning(f"TEST MODE: {msg}")
        else:
            logger.critical(f"FATAL: {msg}")
            sys.exit(1)
    
    check(os.path.exists(config.PRIVATE_KEY_PATH), f"Private key not found")
    check(os.path.exists(config.PUBLIC_KEY_PATH), f"Public key not found")
    
    try:
        key = load_private_key()
        check(key.key_size >= 3072, f"Key {key.key_size} bits < 3072 (V-222543)")
        logger.info(f"Keys verified: RSA-{key.key_size}")
    except Exception as e:
        check(False, f"Key load failed: {e}")


verify_keys()


# ── Helpers ───────────────────────────────────────────────────────────────────

def hash_file_contents(file_stream: IO[bytes], chunk_size: int = 4096) -> Tuple[bytes, int]:
    """Hash file in chunks to handle large files without loading into memory."""
    hasher = hashes.Hash(hashes.SHA256())
    total = 0
    while chunk := file_stream.read(chunk_size):
        hasher.update(chunk)
        total += len(chunk)
    return hasher.finalize(), total


# V-222603: Extension + MIME validation
ALLOWED_MIMETYPES = {
    'txt': {'text/plain'},
    'pdf': {'application/pdf'},
    'doc': {'application/msword'},
    'docx': {'application/vnd.openxmlformats-officedocument.wordprocessingml.document'},
    'png': {'image/png'},
    'jpg': {'image/jpeg'},
}


def validate_file_upload(request_files: Dict, field_name: str = 'file', 
                         check_extension: bool = True) -> Tuple[Optional[object], Optional[str]]:
    if field_name not in request_files:
        return None, 'No file part'
    
    file = request_files[field_name]
    
    if file.filename == '':
        return None, 'No selected file'
    
    if check_extension:
        if not allowed_file(file.filename):
            return None, 'File type not allowed'
        
        ext = file.filename.rsplit('.', 1)[1].lower()
        if ext in ALLOWED_MIMETYPES and file.content_type not in ALLOWED_MIMETYPES[ext]:
            logger.warning(f"MIME mismatch: ext={ext}, type={file.content_type}")
            return None, 'File type mismatch'
    
    return file, None


def audit_log(action: str):
    """Decorator to log security-sensitive operations."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            logger.info(f"AUDIT: {action} - STARTED")
            try:
                result = func(*args, **kwargs)
                logger.info(f"AUDIT: {action} - COMPLETED")
                return result
            except Exception as e:
                logger.error(f"AUDIT: {action} - FAILED: {e}")
                raise
        return wrapper
    return decorator


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    is_locked, remaining = login_tracker.is_locked_out(g.client_ip)
    if is_locked:
        logger.warning(f"AUTH: Locked IP attempted login: {g.client_ip}")
        flash(f'Too many attempts. Try again in {remaining} seconds.', 'error')
        return render_template('login.html')
    
    if request.method == 'POST':
        password = request.form.get('password', '')
        admin_password = os.environ.get('ADMIN_PASSWORD', '')
        
        # V-222604: Timing-safe comparison prevents timing attacks
        if admin_password and secrets.compare_digest(password, admin_password):
            login_tracker.clear(g.client_ip)
            login_user(User('admin'), remember=False)
            logger.info(f"AUTH: Login success from {g.client_ip}")
            flash('Logged in successfully.', 'success')
            
            # Only allow relative URLs to prevent open redirect (V-222609)
            next_page = request.args.get('next', '')
            if next_page and urlparse(next_page).netloc == '':
                return redirect(next_page)
            return redirect(url_for('index'))
        else:
            login_tracker.record_failure(g.client_ip)
            logger.warning(f"AUTH: Failed login from {g.client_ip}")
            flash('Invalid password.', 'error')
    
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logger.info("AUTH: Logout")
    logout_user()
    flash('Logged out.', 'success')
    return redirect(url_for('index'))


@app.route('/sign', methods=['GET', 'POST'])
@login_required
@limiter.limit("5 per minute")
@audit_log("FILE_SIGN")
def sign():
    if request.method == 'POST':
        file, error = validate_file_upload(request.files)
        if error:
            flash(error, 'error')
            return redirect(request.url)

        filename = secure_filename(file.filename)

        try:
            private_key = load_private_key()
            digest, size = hash_file_contents(file)
            
            signature = private_key.sign(digest, PSS_PADDING, utils.Prehashed(hashes.SHA256()))
            
            logger.info(f"SIGN: {filename} ({size} bytes)")
            return send_file(
                io.BytesIO(signature),
                as_attachment=True,
                download_name=f"{filename}.sig",
                mimetype='application/octet-stream'
            )

        except ValueError as e:
            logger.error(f"Key decryption failed: {e}")
            flash("Key access failed.", "error")
            return redirect(request.url)
        except Exception as e:
            logger.error(f"Sign failed: {e}")
            flash("Signing failed.", "error")
            return redirect(request.url)

    return render_template('sign.html')


@app.route('/verify', methods=['GET', 'POST'])
@login_required
@limiter.limit("10 per minute")
@audit_log("FILE_VERIFY")
def verify():
    if request.method == 'POST':
        if 'file' not in request.files or 'signature' not in request.files:
            flash('Missing file or signature', 'error')
            return redirect(request.url)

        file = request.files['file']
        sig_file = request.files['signature']
        
        if file.filename == '' or sig_file.filename == '':
            flash('Select both file and signature', 'error')
            return redirect(request.url)

        if not sig_file.filename.endswith('.sig'):
            flash('Signature must be .sig file', 'error')
            return redirect(request.url)

        filename = secure_filename(file.filename)

        try:
            public_key = load_public_key()
            
            signature = sig_file.read(config.MAX_SIGNATURE_SIZE)
            if len(signature) == config.MAX_SIGNATURE_SIZE and sig_file.read(1):
                flash('Signature too large', 'error')
                return redirect(request.url)
            
            digest, _ = hash_file_contents(file)

            public_key.verify(signature, digest, PSS_PADDING, utils.Prehashed(hashes.SHA256()))
            
            flash('Signature is VALID.', 'success')
            logger.info(f"VERIFY: VALID for {filename}")
            
        except InvalidSignature:
            logger.warning(f"VERIFY: INVALID for {filename}")
            flash('Signature is INVALID.', 'error')
        except Exception as e:
            logger.error(f"Verify failed: {e}")
            flash('Verification failed.', 'error')

        return redirect(url_for('verify'))

    return render_template('verify.html')


@app.route('/api/verify', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
@csrf.exempt
def api_verify():
    """JSON API for programmatic signature verification."""
    from flask import jsonify
    
    if 'file' not in request.files or 'signature' not in request.files:
        return jsonify({'valid': False, 'error': 'Missing file or signature'}), 400
    
    file = request.files['file']
    sig_file = request.files['signature']
    
    if file.filename == '' or sig_file.filename == '':
        return jsonify({'valid': False, 'error': 'Empty filename'}), 400
    
    filename = secure_filename(file.filename)
    
    try:
        signature = sig_file.read()
        if len(signature) > config.MAX_SIGNATURE_SIZE:
            return jsonify({'valid': False, 'error': 'Signature too large'}), 400
        
        digest, size = hash_file_contents(file)
        load_public_key().verify(signature, digest, PSS_PADDING, utils.Prehashed(hashes.SHA256()))
        
        logger.info(f"API_VERIFY: VALID for {filename}")
        return jsonify({'valid': True, 'filename': filename, 'bytes': size})
    
    except InvalidSignature:
        logger.warning(f"API_VERIFY: INVALID for {filename}")
        return jsonify({'valid': False, 'error': 'Invalid signature'})
    except Exception as e:
        logger.error(f"API_VERIFY: Error - {e}")
        return jsonify({'valid': False, 'error': 'Verification failed'}), 500


@app.route('/health')
def health() -> tuple[Dict[str, Any], int]:
    status = 'healthy'
    
    try:
        test_file = os.path.join(config.LOG_DIR, '.health_check')
        with open(test_file, 'w') as f:
            f.write('ok')
        os.remove(test_file)
    except (IOError, OSError):
        status = 'degraded'
    
    return {'status': status, 'timestamp': datetime.now(timezone.utc).isoformat()}, 200 if status == 'healthy' else 503


# ── Error Handlers ────────────────────────────────────────────────────────────

@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(e):
    logger.warning("File too large")
    flash(f"File too large. Max {config.MAX_UPLOAD_SIZE // (1024*1024)}MB.", "error")
    return redirect(request.url)


@app.errorhandler(429)
def ratelimit_handler(e):
    logger.warning("Rate limit exceeded")
    flash("Too many requests.", "error")
    return render_template('index.html'), 429


@app.errorhandler(500)
def internal_error(e):
    logger.error(f"Internal error: {e}")
    flash("Internal error.", "error")
    return render_template('index.html'), 500


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)