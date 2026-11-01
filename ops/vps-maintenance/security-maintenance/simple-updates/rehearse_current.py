#!/usr/bin/python3
"""Supervised same-image Guardian transaction, only when explicitly invoked."""
import fcntl
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import guardian_images as g


def main():
    if os.geteuid() != 0 or sys.argv[1:] != ['--confirm-current-image-rehearsal']:
        raise RuntimeError('requires root and explicit same-image rehearsal confirmation')
    os.umask(0o077)
    lock = os.open('/run/mail-guardian-auto-update.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        g.STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
        if g.MARKER.exists() or g.JOURNAL.exists():
            raise RuntimeError('an earlier transaction requires recovery')
        old = g.CURRENT.resolve(strict=True)
        if old.parent != g.RELEASES:
            raise RuntimeError('unexpected active release')
        g.check_release(old)
        if (g.RUNTIME.read_bytes() != (old / 'deploy/compose.yaml').read_bytes()
                or g.HELPER.read_bytes() != (old / 'maintenance.py').read_bytes()):
            raise RuntimeError('installed release differs from runtime')
        g.atomic(g.JOURNAL, json.dumps({'release': str(old), 'old_release': str(old), 'phase': 'prepared'}).encode(), 0o600)
        try:
            g.run('systemctl', 'disable', '--now', 'mail-guardian@pilot.timer', 'mail-guardian-backup@pilot.timer')
            g.wait_inactive('mail-guardian@pilot.service')
            g.wait_inactive('mail-guardian-backup@pilot.service')
            g.locked_update(old, old)
            g.ssh_check()
            g.run('systemctl', 'start', 'mail-guardian@pilot.service')
            g.run('systemctl', 'enable', '--now', 'mail-guardian@pilot.timer', 'mail-guardian-backup@pilot.timer')
            g.durable_unlink(g.JOURNAL)
            print('Same-image rehearsal complete; actual Guardian run succeeded.')
        except BaseException:
            g.run('systemctl', 'disable', '--now', 'mail-guardian@pilot.timer', 'mail-guardian-backup@pilot.timer', check=False)
            raise
    finally:
        os.close(lock)


if __name__ == '__main__':
    try: main()
    except Exception as exc:
        print('Same-image rehearsal failed: ' + str(exc), file=sys.stderr)
        sys.exit(1)
