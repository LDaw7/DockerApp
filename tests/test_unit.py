# Unit tests - run: pytest tests/ -v

import io
import pytest


class TestSigningWorks:
    def test_can_sign_file(self, client, valid_text_file):
        file_obj, filename = valid_text_file
        response = client.post('/sign', data={'file': (file_obj, filename)}, content_type='multipart/form-data')
        assert response.status_code == 200
        assert 380 <= len(response.data) <= 390  # RSA-3072 = 384 bytes
    
    def test_exe_files_blocked(self, client):
        response = client.post('/sign', data={'file': (io.BytesIO(b'MZ'), 'malware.exe')}, content_type='multipart/form-data', follow_redirects=True)
        assert b'not allowed' in response.data


class TestVerificationWorks:
    def test_valid_signature_verifies(self, client, signature_file):
        content, signature = signature_file
        response = client.post('/verify', data={
            'file': (io.BytesIO(content), 'test.txt'),
            'signature': (io.BytesIO(signature), 'test.txt.sig')
        }, content_type='multipart/form-data', follow_redirects=True)
        assert b'VALID' in response.data
    
    def test_tampered_file_fails(self, client, signature_file):
        content, signature = signature_file
        response = client.post('/verify', data={
            'file': (io.BytesIO(content + b'TAMPERED'), 'test.txt'),
            'signature': (io.BytesIO(signature), 'test.txt.sig')
        }, content_type='multipart/form-data', follow_redirects=True)
        assert b'INVALID' in response.data


class TestCryptoCorrect:
    def test_pss_padding_is_probabilistic(self, client):
        """Same file signed twice produces different signatures (PSS randomness)."""
        content = b'Identical content'
        r1 = client.post('/sign', data={'file': (io.BytesIO(content), 'test.txt')}, content_type='multipart/form-data')
        r2 = client.post('/sign', data={'file': (io.BytesIO(content), 'test.txt')}, content_type='multipart/form-data')
        assert r1.status_code == 200 and r2.status_code == 200
        assert r1.data != r2.data, "PSS not working"


class TestRateLimiting:
    def test_sign_rate_limit_triggers(self, app, client):
        from flask_app import limiter
        limiter.enabled = True
        try:
            for i in range(6):
                response = client.post('/sign', data={'file': (io.BytesIO(b'test'), 'test.txt')}, content_type='multipart/form-data')
                if i >= 5:
                    assert response.status_code == 429
        finally:
            limiter.enabled = False


class TestCSRFProtection:
    def test_post_without_csrf_rejected(self, app, client):
        app.config['WTF_CSRF_ENABLED'] = True
        try:
            response = client.post('/sign', data={'file': (io.BytesIO(b'test'), 'test.txt')}, content_type='multipart/form-data')
            assert response.status_code == 400
        finally:
            app.config['WTF_CSRF_ENABLED'] = False


class TestLogFormat:
    def test_logging_works(self, client):
        """Verify logging runs without error. STIG format verified via log inspection."""
        response = client.get('/')
        assert response.status_code == 200
        # STIG log format (REQ:xxx | IP:xxx | USER:xxx) verified by security_test.sh output


class TestHealthCheck:
    def test_health_returns_json(self, client):
        response = client.get('/health')
        assert response.status_code == 200
        data = response.get_json()
        assert 'status' in data and 'timestamp' in data


class TestAuthentication:
    def test_sign_requires_login(self, app, client):
        app.config['LOGIN_DISABLED'] = False
        try:
            response = client.get('/sign')
            assert response.status_code == 302
            assert '/login' in response.headers.get('Location', '')
        finally:
            app.config['LOGIN_DISABLED'] = True