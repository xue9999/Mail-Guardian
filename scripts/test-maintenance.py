#!/usr/bin/env python3
"""Run isolated maintenance fixture suites; never invoke a production updater."""
from pathlib import Path
import os
import subprocess
import tempfile
import sys

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'ops/vps-maintenance/security-maintenance'
SUITES = [BASE, BASE / 'simple-updates', BASE / 'simple-updates/ubuntu',
          BASE / 'simple-updates/docker', BASE / 'simple-updates/application',
          BASE / 'auto-updates/docker', BASE / 'auto-updates/guardian']
# Journal/path guards intentionally reject world-writable ancestors. Give all
# synthetic subprocesses a private scratch root rather than weakening those
# guards to accommodate Linux's ordinary /tmp. Explicit unsafe-path cases in
# the suites retain their real modes and continue to assert rejection.
with tempfile.TemporaryDirectory(prefix='guardian-maintenance-tests-', dir=Path.home()) as scratch:
    environment = dict(os.environ, TMPDIR=scratch)
    for suite in SUITES:
        print('Fixture suite: ' + str(suite.relative_to(ROOT)), flush=True)
        subprocess.run([sys.executable, '-I', '-m', 'unittest', 'discover',
                        '-s', str(suite), '-p', 'test_*.py'], check=True, cwd=ROOT,
                       env=environment)
