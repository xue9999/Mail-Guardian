"""Independent publication boundary fixtures; no live services or root paths.

Ownership is explicitly virtualized for root-only staged payload checks. Actual
file types, permissions, hashes, exclusive creation, locks and journal writes
remain real temporary-filesystem operations.
"""

import contextlib
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('publish_state_review', Path(__file__).with_name('publish_state.py'))
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)


class PublicationReviewTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)
        self.instance = self.root / 'instance'
        self.instance.mkdir(mode=0o750)
        self.instance.chmod(0o750)
        (self.instance / 'credentials').mkdir(mode=0o700)
        self.pending = self.instance / 'migration-pending'
        self.pending.write_bytes(b'coordinator pending\n')
        self.pending.chmod(0o600)
        self.lock = self.instance / 'migration.lock'
        self.lock.write_bytes(b'')
        self.lock.chmod(0o640)
        self.parent = self.root / 'state'
        self.parent.mkdir(mode=0o700)
        self.data = self.parent / 'pilot'
        self.data.mkdir(mode=0o700)
        self.worker = SimpleNamespace(pw_uid=os.geteuid(), pw_gid=os.getegid())
        self.payload = self.root / 'payload'
        self.payload.mkdir(mode=0o700)
        (self.payload / 'credentials').mkdir(mode=0o700)
        (self.payload / 'archive').mkdir(mode=0o700)
        (self.payload / 'archive' / '2026').mkdir(mode=0o700)
        contents = {
            'config.toml': b'fixture reviewed configuration',
            'guardian.db': b'fixture verified standalone database',
            'credentials/rspamd-password': b'fixture controller secret',
            'credentials/archive-identity': b'fixture archive identity',
            'archive/2026/message.age': b'fixture encrypted archive',
        }
        self.files = {}
        for name, content in contents.items():
            path = self.payload / name
            path.write_bytes(content)
            path.chmod(0o600)
            self.files[name] = hashlib.sha256(content).hexdigest()
        self.manifest = self.root / 'manifest.json'
        self.manifest.write_text(json.dumps({'version': 1, 'files': self.files}))
        self.manifest.chmod(0o600)
        self.manifest_sha = helper.digest(self.manifest)
        self.report_path = self.root / 'publication.json'
        self.inspection = {'messages': 10, 'distinct_archives': 1}
        self.token = 'a' * 32

    def safe_trusted(self, path, *, directory=False, private=False):
        path = Path(path)
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ValueError('fixture unsafe symlink')
        if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
            raise ValueError('fixture unsafe object type')
        if private and stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600):
            raise ValueError('fixture private object required')
        return info

    @contextlib.contextmanager
    def context(self):
        token = SimpleNamespace(hex=self.token)
        def noreplace(source, target):
            helper.absent(Path(target))
            os.rename(source, target)
        with patch.object(helper, 'INSTANCE', self.instance), \
                patch.object(helper, 'DATA', self.data), \
                patch.object(helper, 'trusted', side_effect=self.safe_trusted), \
                patch.object(helper, 'quiescent'), \
                patch.object(helper.os, 'fchown'), \
                patch.object(helper.os, 'chown'), \
                patch.object(helper.uuid, 'uuid4', return_value=token), \
                patch.object(helper, 'rename_new', side_effect=noreplace):
            yield

    @contextlib.contextmanager
    def payload_owner(self):
        original = Path.lstat
        def root_stat(path, *args, **kwargs):
            info = original(path, *args, **kwargs)
            return SimpleNamespace(st_uid=0, st_mode=info.st_mode, st_nlink=info.st_nlink,
                                   st_size=info.st_size, st_gid=info.st_gid,
                                   st_dev=info.st_dev, st_ino=info.st_ino)
        with patch.object(Path, 'lstat', root_stat), \
                patch.object(helper, 'trusted', side_effect=self.safe_trusted):
            yield

    def invoke(self):
        return helper.publish(self.payload, self.files, self.worker, self.report_path,
                              self.inspection, {'release_manifest_sha256': 'b' * 64})

    def test_complete_publication_retains_pending_original_and_imap(self):
        imap = self.instance / 'credentials/imap-password'
        imap.write_bytes(b'independently provisioned fixture credential')
        imap.chmod(0o600)
        original_imap = helper.file_identity(imap.stat()), imap.read_bytes()
        original_data_inode = self.data.stat().st_ino
        with self.context():
            report = self.invoke()
        self.assertTrue(report['success'])
        self.assertTrue(report['migration_pending_preserved'])
        self.assertEqual((helper.file_identity(imap.stat()), imap.read_bytes()), original_imap)
        original = Path(report['original_empty_directory'])
        self.assertEqual(original.stat().st_ino, original_data_inode)
        self.assertEqual(list(original.iterdir()), [])
        self.assertEqual(helper.digest(self.data / 'guardian.db'), self.files['guardian.db'])
        self.assertEqual(helper.digest(self.data / 'archive/2026/message.age'), self.files['archive/2026/message.age'])
        self.assertEqual((self.instance / 'config.toml').stat().st_mode & 0o777, 0o640)
        self.assertEqual((self.instance / 'credentials/archive-identity').stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.pending.read_bytes(), b'coordinator pending\n')
        phases = [json.loads(line)['phase'] for line in Path(report['journal']).read_text().splitlines()]
        self.assertEqual(phases[-1], 'complete-awaiting-policy-adoption')

    def test_existing_config_or_credentials_block_target_publication(self):
        for name in ('config.toml', 'credentials/rspamd-password', 'credentials/archive-identity', 'credentials/unexpected'):
            path = self.instance / name
            path.write_bytes(b'preserve existing')
            path.chmod(0o600)
            before = self.data.stat().st_ino
            with self.subTest(name=name), self.context(), self.assertRaises(ValueError):
                helper.empty_target(self.worker)
            self.assertEqual(path.read_bytes(), b'preserve existing')
            self.assertEqual(self.data.stat().st_ino, before)
            self.assertEqual(list(self.data.iterdir()), [])
            path.unlink()

    def test_existing_report_blocks_before_journal_or_tree_mutations(self):
        self.report_path.write_bytes(b'old report')
        with self.context(), self.assertRaises(ValueError):
            self.invoke()
        self.assertEqual(self.report_path.read_bytes(), b'old report')
        self.assertFalse(self.report_path.with_name(self.report_path.name + '.journal').exists())
        self.assertEqual(list(self.parent.iterdir()), [self.data])

    def test_interruption_after_original_move_retains_marker_and_recovery_trees(self):
        real_rename = os.rename
        calls = 0
        def interrupted(source, target):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError('fixture interruption before data publication')
            real_rename(source, target)
        with self.context(), patch.object(helper, 'rename_new', side_effect=interrupted), self.assertRaisesRegex(OSError, 'interruption'):
            self.invoke()
        self.assertTrue(self.pending.exists())
        self.assertFalse(self.data.exists())
        transaction = self.parent / ('.pilot-publication-' + self.token)
        self.assertEqual(list((transaction / 'original-empty').iterdir()), [])
        self.assertTrue((transaction / 'new-data/guardian.db').is_file())
        self.assertFalse((self.instance / 'config.toml').exists())
        self.assertFalse(self.report_path.exists())
        journal = self.report_path.with_name(self.report_path.name + '.journal')
        last = json.loads(journal.read_text().splitlines()[-1])
        self.assertEqual(last['phase'], 'interrupted-or-failed')
        self.assertEqual(last['last_phase'], 'original-empty-retained')

    def test_source_mismatch_does_not_rename_original_empty_data(self):
        (self.payload / 'guardian.db').write_bytes(b'changed database')
        inode = self.data.stat().st_ino
        with self.context(), self.assertRaisesRegex(ValueError, 'checksum'):
            self.invoke()
        self.assertEqual(self.data.stat().st_ino, inode)
        self.assertEqual(list(self.data.iterdir()), [])
        self.assertTrue(self.pending.exists())
        self.assertFalse((self.instance / 'config.toml').exists())

    def test_pending_marker_is_required_and_must_be_private(self):
        with self.context():
            self.pending.unlink()
            with self.assertRaises(FileNotFoundError), helper.exclusive_fence():
                self.fail('fence entered without pending marker')
            self.pending.write_bytes(b'pending')
            self.pending.chmod(0o640)
            with self.assertRaisesRegex(ValueError, 'private'), helper.exclusive_fence():
                self.fail('fence entered with non-private marker')

    def test_existing_shared_fence_blocks_publication(self):
        with self.lock.open('rb') as stream:
            fcntl.flock(stream, fcntl.LOCK_SH | fcntl.LOCK_NB)
            with self.context(), self.assertRaises(BlockingIOError), helper.exclusive_fence():
                self.fail('exclusive fence entered while reader holds lock')

    def test_payload_manifest_binds_every_file(self):
        with self.payload_owner():
            files, total = helper.verify_payload(self.payload, self.manifest, self.manifest_sha)
            self.assertEqual(files, self.files)
            self.assertGreater(total, 0)
            (self.payload / 'guardian.db').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'checksum'):
                helper.verify_payload(self.payload, self.manifest, self.manifest_sha)

    def test_payload_rejects_traversal_unlisted_files_and_metadata_mismatch(self):
        with self.payload_owner():
            with self.assertRaisesRegex(ValueError, 'checksum'):
                helper.verify_payload(self.payload, self.manifest, '0' * 64)
            extra = self.payload / 'archive/extra.age'
            extra.write_bytes(b'unlisted')
            extra.chmod(0o600)
            with self.assertRaisesRegex(ValueError, 'unlisted'):
                helper.verify_payload(self.payload, self.manifest, self.manifest_sha)
            extra.unlink()
            bad = dict(self.files)
            bad['archive/../../escape'] = '1' * 64
            self.manifest.write_text(json.dumps({'version': 1, 'files': bad}))
            with self.assertRaisesRegex(ValueError, 'path'):
                helper.verify_payload(self.payload, self.manifest, helper.digest(self.manifest))

    def model_report(self):
        return {'success': True, 'cleanup_complete': True, 'normal_config_aof_restart': True,
                'cleanup_errors': 0, 'target_volume': helper.TARGET_VOLUME, 'image': helper.REDIS_IMAGE,
                'retained_volumes': [helper.TARGET_VOLUME], 'source_sha256': 'c' * 64,
                'release_manifest_sha256': 'd' * 64, 'token': self.token,
                'comparisons': [{'equivalent': True}] * 3}

    def test_model_report_is_bound_to_volume_and_complete_comparisons(self):
        report = self.model_report()
        labels = {helper.MODEL_LABEL: self.token, 'com.docker.compose.project': helper.PROJECT,
                  'com.docker.compose.volume': 'redis_data'}
        def docker(*args):
            return json.dumps(labels).encode() if args[0] == 'volume' else b''
        with patch.object(helper, 'read_json', return_value=report), patch.object(helper, 'docker', side_effect=docker):
            self.assertIs(helper.verify_model(self.root / 'model.json', 'a' * 64, 'c' * 64, 'd' * 64), report)
            labels[helper.MODEL_LABEL] = 'f' * 32
            with self.assertRaisesRegex(ValueError, 'does not match'):
                helper.verify_model(self.root / 'model.json', 'a' * 64, 'c' * 64, 'd' * 64)

    @unittest.skipUnless(sys.platform == 'linux', 'actual Linux renameat2 boundary')
    def test_native_noreplace_rename_preserves_existing_destination(self):
        source, destination = self.root / 'rename-source', self.root / 'rename-target'
        source.mkdir()
        destination.mkdir()
        source_inode, target_inode = source.stat().st_ino, destination.stat().st_ino
        with self.assertRaises(OSError):
            helper.rename_new(source, destination)
        self.assertEqual(source.stat().st_ino, source_inode)
        self.assertEqual(destination.stat().st_ino, target_inode)
        destination.rmdir()
        helper.rename_new(source, destination)
        self.assertFalse(source.exists())
        self.assertEqual(destination.stat().st_ino, source_inode)
        for change in ('cleanup_complete', 'normal_config_aof_restart', 'comparisons', 'image'):
            report = self.model_report()
            report[change] = [] if change == 'comparisons' else False
            with self.subTest(change=change), patch.object(helper, 'read_json', return_value=report), \
                    patch.object(helper, 'docker', side_effect=AssertionError('Docker must not be used for an invalid report')), \
                    self.assertRaises(ValueError):
                helper.verify_model(self.root / 'model.json', 'a' * 64, 'c' * 64, 'd' * 64)


if __name__ == '__main__':
    unittest.main()
