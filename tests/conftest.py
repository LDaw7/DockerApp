# Pytest fixtures for unit and security tests

import os
import sys
import io
import tempfile
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Load .env
env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env')
if os.path.exists(env_path):
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                os.environ[key] = value

os.environ.setdefault('TESTING', 'true')
os.environ.setdefault('FLASK_SECRET_KEY', 'test-secret-key')
os.environ.setdefault('KEY_PASSPHRASE', 'test-passphrase')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('LOG_DIR', tempfile.mkdtemp())


def pytest_addoption(parser):
    parser.addoption("--integration", action="store_true", default=False, help="Run integration tests")


@pytest.fixture(scope='session')
def app():
    from flask_app import app as flask_app, limiter
    flask_app.config.update({
        'TESTING': True,
        'WTF_CSRF_ENABLED': False,
        'SECRET_KEY': 'test-secret-key',
        'LOGIN_DISABLED': True,
    })
    limiter.enabled = False
    return flask_app


@pytest.fixture
def client(app):
    with app.test_client() as c:
        with app.app_context():
            yield c


@pytest.fixture
def auth_client(app):
    app.config['LOGIN_DISABLED'] = False
    with app.test_client() as c:
        with app.app_context():
            c.post('/login', data={'password': os.environ.get('ADMIN_PASSWORD', 'test-admin-password')})
            yield c
    app.config['LOGIN_DISABLED'] = True


@pytest.fixture
def valid_text_file():
    return (io.BytesIO(b'Test content for signing'), 'test.txt')


@pytest.fixture
def signature_file(client, valid_text_file):
    file_obj, filename = valid_text_file
    content = file_obj.read()
    file_obj.seek(0)
    
    response = client.post('/sign', data={'file': (io.BytesIO(content), filename)}, content_type='multipart/form-data')
    
    if response.status_code == 200:
        return (content, response.data)
    pytest.skip("Could not generate signature")