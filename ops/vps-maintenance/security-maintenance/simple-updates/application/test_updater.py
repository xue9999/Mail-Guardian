import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import types
import unittest
from unittest.mock import patch

import source_snapshot as source
import updater


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.src = self.root / 'source'; self.src.mkdir()
        self.names = ['go.mod', 'go.sum', 'VERSION', 'Makefile', 'LICENSE', 'README.md',
                      'cmd/guardian/main.go', 'cmd/guardian-recovery/main.go',
                      'internal/config/config.go', 'internal/engine/engine.go']
        for name in self.names:
            path = self.src / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(name)
        self.manifest = {name: source.digest(self.src / name) for name in self.names}

    def tearDown(self): self.temp.cleanup()

    def test_exact_manifest_round_trip_excludes_unreviewed_files(self):
        (self.src / '.env').write_text('secret fixture')
        out = self.root / 'export'
        source.export(self.src, self.manifest, out)
        source.verify_tree(out, self.manifest)
        self.assertFalse((out / '.env').exists())

    def test_credential_and_traversal_names_rejected(self):
        for name in ['deploy/secrets/password.conf', '../go.mod', '/etc/passwd',
                     'tools/credentials/identity.json', 'deploy/.env']:
            with self.subTest(name=name), self.assertRaises(RuntimeError): source.validate_name(name)

    def test_real_reviewed_source_manifest_includes_secret_implementation_only(self):
        manifest = json.loads((Path(__file__).parent / 'testdata/approved-source-manifest.json').read_text())
        self.assertEqual(len(manifest), 238)
        source.validate_manifest(manifest)
        self.assertIn('internal/secrets/credentials.go', manifest)
        for name in ['internal/secrets/password.txt', 'internal/secrets/credentials/identity.go',
                     'deploy/secrets/archive-identity.go', 'internal/secrets/key.age']:
            with self.subTest(name=name), self.assertRaises(RuntimeError): source.validate_name(name)

    def test_source_link_and_content_changes_rejected(self):
        (self.src / 'go.sum').unlink(); (self.src / 'go.sum').symlink_to(self.src / 'go.mod')
        with self.assertRaises((RuntimeError, OSError)):
            source.export(self.src, self.manifest, self.root / 'export')
        self.assertFalse((self.root / 'export').exists())

    def test_unlisted_source_content_rejected(self):
        (self.src / 'internal/extra.go').write_text('unapproved')
        with self.assertRaises(RuntimeError): source.verify_tree(self.src, self.manifest)

    def test_output_symlink_parent_rejected_before_root_read(self):
        (self.root / 'escaped').symlink_to(self.src, target_is_directory=True)
        with self.assertRaises(RuntimeError): updater.artifact_path(self.root / 'escaped/go.mod', self.root)

    def test_output_path_outside_workspace_rejected(self):
        with self.assertRaises(RuntimeError): updater.artifact_path(Path('/etc/passwd'), self.src)

    def test_hardlinked_output_rejected(self):
        os.link(self.src / 'go.mod', self.root / 'hardlink')
        with self.assertRaises(RuntimeError): source.digest(self.root / 'hardlink')
        with self.assertRaises(RuntimeError): updater.copy_artifact(self.root / 'hardlink', self.root / 'copy')

    def test_safe_copy_matches_and_rejects_symlink(self):
        out = self.root / 'copy'; updater.copy_artifact(self.src / 'go.mod', out)
        self.assertEqual(out.read_bytes(), (self.src / 'go.mod').read_bytes())
        out.unlink(); out.symlink_to(self.root / 'outside')
        with self.assertRaises(OSError): updater.copy_artifact(self.src / 'go.mod', out)
        self.assertFalse((self.root / 'outside').exists())

    def test_release_carries_source_and_recovers_missing_private_generation(self):
        state = self.root / 'state'; state.mkdir()
        releases = self.root / 'releases'; releases.mkdir()
        old = releases / 'old'; old.mkdir()
        (old / 'deploy').mkdir(); (old / 'deploy/compose.yaml').write_text('pinned-current-images')
        (old / 'maintenance.py').write_text('current helper')
        runtime = self.root / 'runtime'; runtime.write_bytes((old / 'deploy/compose.yaml').read_bytes())
        helper = self.root / 'helper'; helper.write_bytes((old / 'maintenance.py').read_bytes())
        header = bytearray(20); header[:6] = b'\x7fELF\x02\x01'; header[18:20] = b'\x3e\x00'
        binaries = {}
        for name in ('guardian', 'guardian-recovery'):
            path = self.root / name; path.write_bytes(header + name.encode()); binaries[name] = path
        current = self.root / 'current'; current.symlink_to(old, target_is_directory=True)
        engine = types.SimpleNamespace(CURRENT=current, RELEASES=releases, RUNTIME=runtime, HELPER=helper,
                                       check_release=lambda path: None, sync_tree=lambda path: None,
                                       sync_dir=lambda path: None)
        real_verify = source.verify_tree
        def verify_without_owner(root, manifest, root_owned=False):
            return real_verify(root, manifest, root_owned=False)
        with patch.object(updater, 'STATE', state), patch.object(updater, 'BASELINE', state / 'baseline.json'), \
             patch.object(updater, 'trusted_file'), patch.object(source, 'verify_tree', side_effect=verify_without_owner):
            record = updater.source_record(self.src, self.manifest, compiler_version='go1.27.3',
                    binaries={name: source.digest(path) for name, path in binaries.items()})
            _, target = updater.make_release(engine, binaries, record, {'fixture': 'qualified'})
            self.assertEqual((target / 'deploy/compose.yaml').read_text(), 'pinned-current-images')
            for name in self.manifest:
                self.assertEqual(source.digest(target / 'application-source' / name), self.manifest[name])
                self.assertIn('  application-source/' + name + '\n', (target / 'SHA256SUMS').read_text())
            current.unlink(); current.symlink_to(target, target_is_directory=True)
            shutil.rmtree(state / 'sources')
            updater.promote_from_current(engine)
            adopted = json.loads((state / 'baseline.json').read_text())
            self.assertEqual(adopted['tree_sha256'], record['tree_sha256'])
            real_verify(Path(adopted['source_directory']), self.manifest)

    def test_failed_qualification_preserves_bounded_diagnostics_not_cache(self):
        state = self.root / 'state'; state.mkdir()
        work = state / 'build-fixture'; work.mkdir()
        (work / 'prepare.log').touch()
        (work / 'offline-qualification.log').write_text('specific compatibility failure')
        (work / 'sandbox').mkdir(); (work / 'sandbox/cache').write_text('disposable cache')
        with patch.object(updater, 'STATE', state), patch.object(updater, 'trusted_file'):
            updater.preserve_failure(work, RuntimeError('offline test failed'))
        shutil.rmtree(work)
        self.assertEqual((state / 'last-failure/offline-qualification.log').read_text(), 'specific compatibility failure')
        self.assertIn('offline test failed', (state / 'last-failure/failure.json').read_text())
        self.assertEqual((state / 'last-failure/prepare.log').stat().st_size, 0)
        self.assertFalse((state / 'last-failure/sandbox').exists())


class CoordinationTests(unittest.TestCase):
    def test_payload_bound_allows_real_binaries_larger_than_metadata_bound(self):
        path = Path('/controlled/inbox/payload/guardian')
        def info(target):
            return types.SimpleNamespace(st_uid=0, st_nlink=1, st_size=13 << 20,
                                         st_mode=(stat.S_IFREG | 0o600) if target == path else (stat.S_IFDIR | 0o700))
        with patch.object(Path, 'lstat', autospec=True, side_effect=info):
            with self.assertRaises(RuntimeError): updater.trusted_file(path)
            updater.trusted_file(path, limit=64 << 20)

    def test_own_pending_check_refuses_without_service_commands(self):
        with tempfile.TemporaryDirectory() as raw:
            state = Path(raw); pending = state / 'pending'; pending.write_text('{}')
            calls = []
            engine = types.SimpleNamespace(run=lambda *args: calls.append(args))
            with patch.object(updater, 'load_engine', return_value=engine), \
                 patch.object(updater, 'STATE', state), patch.object(updater, 'PENDING', pending), \
                 patch.object(updater, 'OTHER_PENDING', ()):
                with self.assertRaisesRegex(RuntimeError, 'will not recover'):
                    updater.execute(check_only=True)
            self.assertFalse(calls)

    def test_builder_receives_new_workspace(self):
        import builder
        with tempfile.TemporaryDirectory() as raw:
            state = Path(raw); source = state / 'source'; source.mkdir()
            (source / 'VERSION').write_text('0.6.1')
            engine = types.SimpleNamespace(MARKER=state / 'marker')
            # Exercise the real builder's initial filesystem contract and stop
            # before external discovery. A caller-created dir fails earlier.
            stop = RuntimeError('past-new-workspace-contract')
            with patch.object(updater, 'load_engine', return_value=engine), \
                 patch.object(updater, 'STATE', state), patch.object(updater, 'PENDING', state / 'pending'), \
                 patch.object(updater, 'OTHER_PENDING', ()), \
                 patch.object(updater, 'promote_from_current'), \
                 patch.object(updater, 'load_baseline', return_value={'tree_sha256': 'fixture'}), \
                 patch.object(updater, 'check_record', return_value=source), \
                 patch.object(updater, 'remote_discovery', return_value={}), \
                 patch.object(builder, 'discover', return_value={'fingerprint': 'fixture',
                    'dependency_plan': {'modules': {}}, 'compiler_version': '1.27.3',
                    'govulncheck_version': 'v1.9.0', 'vulnerability_db_modified': 'stamp'}), \
                 patch.object(builder, '_copy_source', side_effect=stop):
                with self.assertRaisesRegex(RuntimeError, 'past-new-workspace-contract'):
                    updater.execute()

    def test_unchanged_fingerprint_skips_cold_build_and_new_database_requalifies(self):
        self.assertTrue(updater.no_candidate_since_qualification({'fingerprint': 'same'},
                        {'discovery_fingerprint': 'same'}))
        self.assertFalse(updater.no_candidate_since_qualification({'fingerprint': 'new-database'},
                         {'discovery_fingerprint': 'old-database'}))

    def test_bootstrap_normalizes_go_prefix_and_only_skips_exact_qualified_inputs(self):
        discovery = {'fingerprint': 'new', 'compiler_version': '1.27.3', 'govulncheck_version': 'v1.9.0',
                     'vulnerability_db_modified': 'stamp',
                     'dependency_plan': {'modules': {'example.org/mod': {'current': 'v1.2.3', 'candidate': 'v1.2.3'}}}}
        baseline = {'compiler_version': 'go1.27.3', 'qualification_config':
                    {'govulncheck_version': 'v1.9.0', 'vulnerability_db_modified': 'stamp'}}
        self.assertTrue(updater.no_candidate_since_qualification(discovery, baseline))
        discovery['dependency_plan']['modules']['example.org/mod']['candidate'] = 'v1.2.4'
        self.assertFalse(updater.no_candidate_since_qualification(discovery, baseline))

    def test_other_pending_prevents_build_or_activation(self):
        with tempfile.TemporaryDirectory() as raw:
            state = Path(raw); pending = state / 'other'; pending.write_text('{}')
            engine = types.SimpleNamespace()
            with patch.object(updater, 'load_engine', return_value=engine), \
                 patch.object(updater, 'STATE', state), patch.object(updater, 'PENDING', state / 'own'), \
                 patch.object(updater, 'OTHER_PENDING', (pending,)):
                updater.execute()

    def test_source_discovery_never_installs_older_mac_release(self):
        output = types.SimpleNamespace(stdout='559b7cd87926039cd23a2f170dd89de3f80a6fce\trefs/tags/v0.5.1\n')
        with patch.object(updater.subprocess, 'run', return_value=output):
            result = updater.remote_discovery('0.6.1')
        self.assertFalse(result['newer_source_release_detected'])
        self.assertIsNone(result['source_installation_blocker'])

    def test_new_major_source_is_detected_with_concrete_qualification_gate(self):
        output = types.SimpleNamespace(stdout='559b7cd87926039cd23a2f170dd89de3f80a6fce\trefs/tags/v2.0.0\n')
        with patch.object(updater.subprocess, 'run', return_value=output):
            result = updater.remote_discovery('0.6.1')
        self.assertTrue(result['newer_source_release_detected'])
        self.assertIn('reviewed Linux-compatible', result['source_installation_blocker'])

    def test_failed_activation_keeps_pending_and_fences_timers(self):
        with tempfile.TemporaryDirectory() as raw:
            pending = Path(raw) / 'pending.json'
            calls = []
            def run(*args, **kwargs): calls.append(args)
            engine = types.SimpleNamespace(run=run, wait_inactive=lambda unit: None,
                                           locked_update=lambda *args: (_ for _ in ()).throw(RuntimeError('failure')))
            with patch.object(updater, 'PENDING', pending):
                with self.assertRaises(RuntimeError): updater.activate(engine, Path('/old'), Path('/new'))
            self.assertTrue(pending.exists())
            self.assertEqual(calls[-1][:3], ('systemctl', 'disable', '--now'))


if __name__ == '__main__': unittest.main()
