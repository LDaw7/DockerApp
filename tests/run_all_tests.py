#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────────────
# Test Runner
# ──────────────────────────────────────────────────────────────────────────────
# Simple test runner for unit and security tests.
#
#   python run_all_tests.py           → run all tests
#   python run_all_tests.py --unit    → unit tests only
#   python run_all_tests.py --security→ security tests only
#
# [L7Dawson]

import sys
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent


def run_tests(test_file=None):
    """Run pytest with optional file filter."""
    cmd = [sys.executable, '-m', 'pytest', 'tests/', '-v', '--tb=short']
    
    if test_file:
        cmd = [sys.executable, '-m', 'pytest', f'tests/{test_file}', '-v', '--tb=short']
    
    result = subprocess.run(cmd, cwd=str(PROJECT_ROOT))
    return result.returncode


if __name__ == '__main__':
    if '--unit' in sys.argv:
        sys.exit(run_tests('test_unit.py'))
    elif '--security' in sys.argv:
        sys.exit(run_tests('test_security.py'))
    else:
        sys.exit(run_tests())
