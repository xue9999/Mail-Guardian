#!/usr/bin/env python3
"""Run isolated maintenance fixture suites; never invoke a production updater."""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'ops/vps-maintenance/security-maintenance'
SUITES = [BASE, BASE / 'simple-updates', BASE / 'simple-updates/ubuntu',
          BASE / 'simple-updates/docker', BASE / 'simple-updates/application',
          BASE / 'auto-updates/docker', BASE / 'auto-updates/guardian']
for suite in SUITES:
    print('Fixture suite: ' + str(suite.relative_to(ROOT)), flush=True)
    subprocess.run([sys.executable, '-I', '-m', 'unittest', 'discover',
                    '-s', str(suite), '-p', 'test_*.py'], check=True, cwd=ROOT)
