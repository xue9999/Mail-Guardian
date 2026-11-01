import json
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import guardian_images as g


class UpdateTests(unittest.TestCase):
    def test_release_manifest_accepts_systemd_template_name(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / 'guardian@.service').write_bytes(b'test')
            (root / 'SHA256SUMS').write_text(hashlib.sha256(b'test').hexdigest() + '  guardian@.service\n')
            g.check_release(root)
    def test_production_execution_is_hard_disabled(self):
        with mock.patch.object(g.os, 'geteuid', return_value=0), mock.patch.object(g, 'PRODUCTION_READY', False), mock.patch.object(g, 'execute') as execute:
            with self.assertRaisesRegex(RuntimeError, 'automatic activation disabled'):
                g.main()
            execute.assert_not_called()

    def test_preflight_rejects_changed_rspamd_user_before_running_image(self):
        image = {'Os': 'linux', 'Architecture': 'amd64', 'RepoDigests': ['rspamd/rspamd@sha256:' + '1' * 64],
                 'Config': {'User': '123:123', 'Volumes': {'/var/lib/rspamd': {}}}}
        row = {'repo': 'rspamd/rspamd', 'candidate': {'ref': 'example', 'index_digest': 'sha256:' + '1' * 64}}
        with mock.patch.object(g, 'run', return_value=mock.Mock(stdout=json.dumps(image))), mock.patch.object(g, 'isolated_command') as isolated:
            with self.assertRaisesRegex(RuntimeError, 'runtime user'):
                g.preflight([row])
            isolated.assert_not_called()

    def test_atomic_sets_requested_mode_despite_umask(self):
        with tempfile.TemporaryDirectory() as raw:
            target = Path(raw) / 'file'
            mask = os.umask(0o077)
            try: g.atomic(target, b'ok', 0o755)
            finally: os.umask(mask)
            self.assertEqual(target.stat().st_mode & 0o777, 0o755)
            self.assertEqual(target.read_bytes(), b'ok')

    def test_staged_tree_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / 'file').write_text('data')
            (root / 'link').symlink_to(root / 'file')
            with self.assertRaises(OSError):
                g.sync_tree(root)

    def test_lone_journal_or_marker_disables_timers_and_refuses_recovery(self):
        for artifact in ('journal', 'marker'):
            with self.subTest(artifact=artifact), tempfile.TemporaryDirectory() as raw:
                state = Path(raw)
                marker, journal = state / 'marker', state / 'journal'
                (journal if artifact == 'journal' else marker).write_text('pending')
                with mock.patch.multiple(g, STATE=state, JOURNAL=journal, MARKER=marker, PRODUCTION_READY=True), mock.patch.object(g, 'run') as run, \
                     mock.patch.object(g, 'wait_inactive'), mock.patch.object(g, 'recover_pending', side_effect=RuntimeError('manual inspection')):
                    with self.assertRaisesRegex(RuntimeError, 'manual inspection'):
                        g.execute()
                    run.assert_called_once_with('systemctl', 'disable', '--now', 'mail-guardian@pilot.timer', 'mail-guardian-backup@pilot.timer')
                    self.assertTrue((journal if artifact == 'journal' else marker).exists())

    def test_recovery_rejects_orphan_marker_and_invalid_paths(self):
        with tempfile.TemporaryDirectory() as raw:
            journal = Path(raw) / 'journal'
            with mock.patch.object(g, 'JOURNAL', journal):
                with self.assertRaisesRegex(RuntimeError, 'orphan'):
                    g.recover_pending()
                journal.write_text(json.dumps({'old_release': '/tmp/old', 'release': '/tmp/new', 'phase': 'prepared'}))
                with self.assertRaisesRegex(RuntimeError, 'invalid'):
                    g.recover_pending()

    def test_postflight_failure_retains_journal_and_disables_timers(self):
        with tempfile.TemporaryDirectory() as raw:
            state = Path(raw)
            journal, marker = state / 'journal', state / 'marker'
            events = []
            report = {'errors': [], 'attention': True, 'images': [{'candidate': {'ref': 'test'}}]}
            def command(*args, **kwargs):
                events.append(args)
                if args[:3] == ('systemctl', 'show', 'mail-guardian-backup@pilot.service'):
                    return mock.Mock(stdout='success\n')
                if args == ('systemctl', 'start', 'mail-guardian@pilot.service'):
                    raise RuntimeError('mailbox run failed after possible changes')
                return mock.Mock(stdout='')
            with mock.patch.multiple(g, STATE=state, JOURNAL=journal, MARKER=marker, PRODUCTION_READY=True), \
                 mock.patch.object(g.image_discovery, 'parse_compose', return_value={}), \
                 mock.patch.object(g.image_discovery, 'discover', return_value=report), \
                 mock.patch.object(g, 'run', side_effect=command), mock.patch.object(g, 'preflight'), \
                 mock.patch.object(g, 'make_release', return_value=(Path('/old'), Path('/new'))), \
                 mock.patch.object(g, 'wait_inactive'), mock.patch.object(g, 'locked_update'), mock.patch.object(g, 'ssh_check'):
                with self.assertRaisesRegex(RuntimeError, 'mailbox run failed'):
                    g.execute()
                self.assertEqual(json.loads(journal.read_text())['phase'], 'prepared')
                self.assertEqual(events[-1][:3], ('systemctl', 'disable', '--now'))
                self.assertFalse(any(e[:3] == ('systemctl', 'enable', '--now') for e in events))

    def test_unavailable_component_does_not_block_valid_update(self):
        with tempfile.TemporaryDirectory() as raw:
            state = Path(raw)
            journal, marker = state / 'journal', state / 'marker'
            report = {'errors': [{'repo': 'one', 'error': 'unavailable'}], 'attention': True,
                      'images': [{'candidate': {'ref': 'valid'}}]}
            events = []
            def command(*args, **kwargs):
                events.append(args)
                return mock.Mock(stdout='', returncode=0)
            with mock.patch.multiple(g, STATE=state, JOURNAL=journal, MARKER=marker, PRODUCTION_READY=True), \
                 mock.patch.object(g.image_discovery, 'parse_compose', return_value={}), \
                 mock.patch.object(g.image_discovery, 'discover', return_value=report), \
                 mock.patch.object(g, 'run', side_effect=command), mock.patch.object(g, 'preflight'), \
                 mock.patch.object(g, 'make_release', return_value=(Path('/old'), Path('/new'))), \
                 mock.patch.object(g, 'wait_inactive'), mock.patch.object(g, 'locked_update'), mock.patch.object(g, 'ssh_check'):
                with self.assertRaisesRegex(RuntimeError, 'remain blocked'):
                    g.execute()
                self.assertTrue(any(e[:3] == ('systemctl', 'enable', '--now') for e in events))
                self.assertEqual(events[-1][:3], ('systemctl', 'enable', '--now'))
                self.assertFalse(journal.exists())

    def test_recovery_only_with_no_pending_state_has_no_side_effects(self):
        with tempfile.TemporaryDirectory() as raw:
            state = Path(raw)
            with mock.patch.multiple(g, STATE=state, JOURNAL=state / 'journal', MARKER=state / 'marker',
                                     DOCKER_PENDING=state / 'docker-pending'), \
                 mock.patch.object(g, 'run') as run, mock.patch.object(g.image_discovery, 'discover') as discover:
                g.execute(recovery_only=True)
                run.assert_not_called()
                discover.assert_not_called()

    def test_no_update_only_refuses_candidate_without_pulling(self):
        with tempfile.TemporaryDirectory() as raw:
            state = Path(raw)
            report = {'errors': [], 'attention': True, 'images': [{'candidate': {'ref': 'candidate'}}]}
            with mock.patch.multiple(g, STATE=state, JOURNAL=state / 'journal', MARKER=state / 'marker',
                                     DOCKER_PENDING=state / 'docker-pending'), \
                 mock.patch.object(g.image_discovery, 'parse_compose', return_value={}), \
                 mock.patch.object(g.image_discovery, 'discover', return_value=report), mock.patch.object(g, 'run') as run:
                with self.assertRaisesRegex(RuntimeError, 'will not install'):
                    g.execute(no_update_only=True)
                run.assert_not_called()

    def test_global_lock_contention_is_benign(self):
        with mock.patch.object(g.os, 'geteuid', return_value=0), mock.patch.object(g.os, 'umask'), \
             mock.patch.object(g.os, 'open', return_value=42), mock.patch.object(g.os, 'close'), \
             mock.patch.object(g.fcntl, 'flock', side_effect=BlockingIOError), \
             mock.patch.object(g.sys, 'argv', ['guardian_images.py']), mock.patch.object(g, 'execute') as execute:
            g.main()
            execute.assert_not_called()


if __name__ == '__main__':
    unittest.main()
