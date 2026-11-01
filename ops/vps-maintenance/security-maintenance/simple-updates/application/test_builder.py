"""Offline safety checks for the approved-source candidate builder."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


_SPEC = importlib.util.spec_from_file_location("guardian_application_builder", Path(__file__).with_name("builder.py"))
builder = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(builder)


class VersionSelectionTests(unittest.TestCase):
    def test_stable_selection_excludes_preview_pseudo_and_malformed_tags(self):
        versions = ["v1.2.1", "v1.3.0-beta.2", "v1.3.0-rc.1", "v1.2.3",
                    "v1.2.4-0.20261030120000-deadbeef", "v01.9.0", "garbage"]
        self.assertEqual(builder.choose_stable(versions, "v1.2.0"), "v1.2.3")

    def test_major_and_minor_stable_updates_are_considered(self):
        self.assertEqual(builder.choose_stable(["v1.9.0", "v2.0.0", "v1.10.0"], "v1.0.0"), "v2.0.0")

    def test_existing_preview_is_not_downgraded_to_older_stable_series(self):
        self.assertEqual(builder.choose_stable(["v1.2.1"], "v2.0.0-beta.8"), "v2.0.0-beta.8")
        self.assertEqual(builder.choose_stable(["v2.0.0"], "v2.0.0-beta.8"), "v2.0.0")

    def test_newer_existing_stable_is_not_silently_downgraded(self):
        self.assertEqual(builder.choose_stable(["v1.0.0"], "v1.0.1"), "v1.0.1")

    def test_module_proxy_path_escaping_and_traversal_rejection(self):
        self.assertEqual(builder._module_path("github.com/BurntSushi/toml"), "github.com/!burnt!sushi/toml")
        for value in ("../etc", "example.com/../etc", "example.com/a?token=x", "example.com/a\nheader"):
            with self.subTest(value=value), self.assertRaises(builder.BuildError):
                builder._module_path(value)

    def test_next_major_replaces_existing_major_suffix(self):
        self.assertEqual(builder._next_major("example.com/a", "v0.8.0"), "example.com/a/v2")
        self.assertEqual(builder._next_major("example.com/a/v2", "v2.9.0"), "example.com/a/v3")
        self.assertEqual(builder._next_major("example.com/a/v12", "v12.9.0"), "example.com/a/v13")


class DependencyPlanTests(unittest.TestCase):
    def test_scheduled_plan_retains_patches_and_reports_new_minor(self):
        versions = ["v1.2.0", "v1.2.1", "v1.3.0", "v2.0.0"]
        with patch.object(builder, "_versions", side_effect=lambda module, **kw: versions if module == "example.com/a" else []):
            plan = builder.dependency_plan([{"Path": "example.com/a", "Version": "v1.2.0"}], patch_only=True)
        self.assertEqual(plan['modules']['example.com/a']['candidate'], 'v1.2.1')
        self.assertTrue(any('manual review' in row['reason'] for row in plan['blockers']))

    def test_imap_preview_retained_with_concrete_major_migration_blocker(self):
        versions = {"example.com/imap/v2": ["v2.0.0-beta.8", "v2.0.0-beta.9"],
                    "example.com/imap/v3": ["v3.0.0", "v3.1.0-rc.1"]}
        with patch.object(builder, "_versions", side_effect=lambda module, **kwargs: versions.get(module, [])):
            plan = builder.dependency_plan([{"Path": "example.com/imap/v2", "Version": "v2.0.0-beta.8"}])
        self.assertEqual(plan["modules"]["example.com/imap/v2"]["candidate"], "v2.0.0-beta.8")
        self.assertEqual(len(plan["blockers"]), 2)
        self.assertTrue(all(x.get("next_action") for x in plan["blockers"]))
        self.assertEqual(plan["blockers"][1]["detected_module"], "example.com/imap/v3")
        self.assertEqual(plan["blockers"][1]["detected"], "v3.0.0")

    def test_sqlite_uses_exact_publisher_libc_pair_and_records_newer_blocker(self):
        versions = {"modernc.org/sqlite": ["v1.54.0", "v1.61.1", "v1.62.0-rc.1"],
                    "modernc.org/libc": ["v1.74.1", "v1.79.0", "v1.79.1"]}
        upstream_mod = "module modernc.org/sqlite\nrequire (\n modernc.org/libc v1.79.0\n)\n"
        required = [{"Path": "modernc.org/sqlite", "Version": "v1.54.0"},
                    {"Path": "modernc.org/libc", "Version": "v1.74.1"}]
        with patch.object(builder, "_versions", side_effect=lambda module, **kwargs: versions.get(module, [])), \
             patch.object(builder, "_fetch_text", return_value=upstream_mod):
            plan = builder.dependency_plan(required)
        self.assertEqual(plan["modules"]["modernc.org/sqlite"]["candidate"], "v1.61.1")
        self.assertEqual(plan["modules"]["modernc.org/libc"]["candidate"], "v1.79.0")
        self.assertTrue(any(x.get("detected") == "v1.79.1" and x.get("compatible") == "v1.79.0"
                            for x in plan["blockers"]))

    def test_missing_or_preview_sqlite_libc_pin_fails_closed(self):
        for text in ("module modernc.org/sqlite\n", "require (\n modernc.org/libc v1.80.0-beta.1\n)\n"):
            with self.subTest(text=text), self.assertRaises(builder.BuildError):
                builder.sqlite_libc_pin(text)


class FilesystemSafetyTests(unittest.TestCase):
    def test_test_temp_directory_is_created_on_the_disk_workspace(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source = root / 'source'; source.mkdir()
            (source / 'go.mod').write_text('module example.com/test\n')
            (source / 'go.sum').write_text('')
            (source / 'VERSION').write_text('0.6.1\n')
            with patch.object(builder, 'discover', side_effect=builder.BuildError('stop before network')):
                with self.assertRaisesRegex(builder.BuildError, 'stop before network'):
                    builder.build_candidate(source, root / 'build')
            scratch = root / 'build/sandbox'
            test_tmp = scratch / 'test-tmp'
            self.assertTrue(test_tmp.is_dir())
            self.assertEqual(test_tmp.stat().st_mode & 0o7777, 0o1777)
            self.assertEqual(scratch.stat().st_mode & 0o7777, 0o1777)
            self.assertEqual(test_tmp.stat().st_dev, scratch.stat().st_dev)

    def test_source_is_readable_by_container_under_private_service_umask(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "sub").mkdir()
            for name in ("go.mod", "go.sum", "VERSION", "sub/script.sh"):
                (source / name).write_text("0.6.1\n")
            (source / "sub/script.sh").chmod(0o755)
            previous = os.umask(0o077)
            try:
                builder._copy_source(source, root / "approved")
            finally:
                os.umask(previous)
            for path in (root / "approved", root / "approved/sub"):
                self.assertEqual(path.stat().st_mode & 0o777, 0o755)
            self.assertEqual((root / "approved/sub/script.sh").stat().st_mode & 0o777, 0o755)

    def test_fifo_is_refused_without_blocking(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fifo"
            os.mkfifo(path)
            with self.assertRaises(builder.BuildError):
                builder._safe_read(path, Path(temporary))

    def test_root_log_never_overwrites_a_planted_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "untouched"
            target.write_text("original")
            log = root / "log"
            log.symlink_to(target)
            with self.assertRaises(builder.BuildError):
                builder._run([sys.executable, "-c", "print('ordinary command')"], log=log)
            self.assertEqual(target.read_text(), "original")

    def test_subprocess_output_cannot_exceed_host_capture_bound(self):
        with self.assertRaisesRegex(builder.BuildError, "bounded log limit"):
            builder._run([sys.executable, "-c", "import os; os.write(1,b'x'*(17<<20))"])

    def test_source_copy_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "go.mod").write_text("module example.com/test\n")
            (source / "go.sum").write_text("")
            (source / "VERSION").write_text("0.6.1\n")
            (source / "linked").symlink_to(source / "VERSION")
            with self.assertRaises(builder.BuildError):
                builder._copy_source(source, root / "copy")

    def test_safe_read_rejects_symlink_file_parent_hardlink_and_oversize(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inside = root / "inside"
            inside.mkdir()
            outside = root / "outside"
            outside.mkdir()
            secret = outside / "value"
            secret.write_bytes(b"private")
            (inside / "linked").symlink_to(secret)
            (inside / "linked-parent").symlink_to(outside, target_is_directory=True)
            (inside / "oversize").write_bytes(b"12345")
            (inside / "plain").write_bytes(b"ok")
            (inside / "hardlink").hardlink_to(secret)
            for path, maximum in ((inside / "linked", 32), (inside / "linked-parent" / "value", 32),
                                  (inside / "hardlink", 32), (inside / "oversize", 4)):
                with self.subTest(path=path), self.assertRaises(builder.BuildError):
                    builder._safe_read(path, inside, maximum)
            self.assertEqual(builder._safe_read(inside / "plain", inside, 4), b"ok")

    def test_existing_work_directory_is_refused_before_upstream_or_docker(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(builder, "_compiler_and_image") as upstream, patch.object(builder, "_run") as command:
                with self.assertRaises(builder.BuildError):
                    builder.build_candidate(root, root)
            upstream.assert_not_called()
            command.assert_not_called()

    def test_module_files_can_change_but_app_source_addition_removal_or_edit_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "src"
            source.mkdir()
            (source / "go.mod").write_text("module example.com/test\n")
            (source / "main.go").write_text("package main\n")
            manifest = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in source.iterdir()}
            (source / "go.mod").write_text("module example.com/test\ngo 1.27.0\n")
            builder._source_unchanged(source, manifest, root)
            (source / "added.go").write_text("package main\n")
            with self.assertRaises(builder.BuildError):
                builder._source_unchanged(source, manifest, root)
            (source / "added.go").unlink()
            (source / "main.go").write_text("package changed\n")
            with self.assertRaises(builder.BuildError):
                builder._source_unchanged(source, manifest, root)
            (source / "main.go").unlink()
            with self.assertRaises(builder.BuildError):
                builder._source_unchanged(source, manifest, root)


class ImageAndContainerTests(unittest.TestCase):
    def _image_fixture(self, config_arch="amd64"):
        config = json.dumps({"os": "linux", "architecture": config_arch})
        config_digest = "sha256:" + hashlib.sha256(config.encode()).hexdigest()
        manifest = json.dumps({"schemaVersion": 2, "config": {"digest": config_digest}})
        digest = "sha256:" + hashlib.sha256(manifest.encode()).hexdigest()
        index = json.dumps({"manifests": [{"platform": {"os": "linux", "architecture": "amd64"}, "digest": digest}]})
        def fetch_json(url, **kwargs):
            if "go.dev/dl/" in url:
                return [{"version": "go1.27.3", "stable": True}, {"version": "go1.28rc1", "stable": False},
                        {"version": "go1.26.8", "stable": True}]
            return {"token": "anonymous-public-token"}
        def fetch_text(url, **kwargs):
            if url.endswith("/manifests/1.27.3"):
                return index
            if url.endswith("/manifests/" + digest):
                return manifest
            if url.endswith("/blobs/" + config_digest):
                return config
            self.fail("unexpected upstream request: " + url)
        return fetch_json, fetch_text, digest

    def test_official_compiler_resolves_exact_amd64_manifest_and_checks_config(self):
        fetch_json, fetch_text, digest = self._image_fixture()
        with patch.object(builder, "_fetch_json", side_effect=fetch_json), patch.object(builder, "_fetch_text", side_effect=fetch_text):
            version, image = builder._compiler_and_image()
        self.assertEqual(version, "1.27.3")
        self.assertEqual(image, "docker.io/library/golang@" + digest)

    def test_scheduled_compiler_retains_approved_minor_line(self):
        fetch_json, fetch_text, digest = self._image_fixture()
        def with_new_line(url, **kwargs):
            result = fetch_json(url, **kwargs)
            if 'go.dev/dl/' in url:
                return result + [{'version': 'go1.28.0', 'stable': True}]
            return result
        with patch.object(builder, '_fetch_json', side_effect=with_new_line), \
             patch.object(builder, '_fetch_text', side_effect=fetch_text):
            review = {}
            version, image = builder._compiler_and_image('1.27.2', review=review)
        self.assertEqual(version, '1.27.3')
        self.assertEqual(image, 'docker.io/library/golang@' + digest)
        self.assertEqual(review['detected'], '1.28.0')

    def test_manifest_config_architecture_mismatch_is_refused(self):
        fetch_json, fetch_text, _ = self._image_fixture("arm64")
        with patch.object(builder, "_fetch_json", side_effect=fetch_json), patch.object(builder, "_fetch_text", side_effect=fetch_text):
            with self.assertRaises(builder.BuildError):
                builder._compiler_and_image()

    def test_manifest_bytes_must_match_registry_descriptor_digest(self):
        fetch_json, fetch_text, digest = self._image_fixture()
        def changed_fetch(url, **kwargs):
            value = fetch_text(url, **kwargs)
            return value + " " if url.endswith("/manifests/" + digest) else value
        with patch.object(builder, "_fetch_json", side_effect=fetch_json), patch.object(builder, "_fetch_text", side_effect=changed_fetch):
            with self.assertRaises(builder.BuildError):
                builder._compiler_and_image()

    def test_ambiguous_amd64_manifests_are_refused(self):
        fetch_json, fetch_text, _ = self._image_fixture()
        def ambiguous_fetch(url, **kwargs):
            value = fetch_text(url, **kwargs)
            if url.endswith("/manifests/1.27.3"):
                document = json.loads(value)
                document["manifests"] += document["manifests"]
                return json.dumps(document)
            return value
        with patch.object(builder, "_fetch_json", side_effect=fetch_json), patch.object(builder, "_fetch_text", side_effect=ambiguous_fetch):
            with self.assertRaises(builder.BuildError):
                builder._compiler_and_image()

    def test_offline_container_is_unprivileged_bounded_and_mounts_source_readonly(self):
        calls = []
        token = "a" * 32
        name = "mg-app-build-" + token + "-offline"
        def run(args, **kwargs):
            calls.append(args)
            return ""
        with tempfile.TemporaryDirectory() as temporary, patch.object(builder, "_run", side_effect=run):
            work = Path(temporary)
            builder._container("docker.io/library/golang@sha256:" + "1" * 64,
                               Path("/approved"), work, "go test -race ./...", token, "offline", network="none")
        command = next(c for c in calls if "run" in c)
        for flag, value in (("--user", "65534:65534"), ("--memory", "1536m"),
                            ("--cpus", "1"), ("--pids-limit", "256"), ("--network", "none"),
                            ("--security-opt", "no-new-privileges")):
            self.assertEqual(command[command.index(flag) + 1], value)
        self.assertIn("--cap-drop=ALL", command)
        self.assertIn("--read-only", command)
        self.assertIn("type=bind,source=/approved,target=/source,readonly", command)
        mounts = [command[i + 1] for i, item in enumerate(command[:-1]) if item == "--mount"]
        self.assertFalse(any("docker.sock" in mount or "/var/lib/mail-guardian" in mount for mount in mounts))
        self.assertFalse(any("prune" in c for c in calls))
        self.assertTrue(any(name in " ".join(c) for c in calls))

    @unittest.skipUnless(shutil.which('go'), 'Go unavailable for actual T.TempDir integration fixture')
    def test_selected_temp_env_reaches_real_go_tempdir_and_reserve_check(self):
        calls = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); work = root / 'sandbox'; work.mkdir()
            with patch.object(builder, '_run', side_effect=lambda args, **kwargs: calls.append(args) or ''):
                builder._container('docker.io/library/golang@sha256:' + '1' * 64,
                    Path('/approved'), work, 'go test -race ./...', 'e' * 32, 'offline', network='none')
            command = next(item for item in calls if 'run' in item)
            environment = dict(command[i + 1].split('=', 1) for i, flag in enumerate(command[:-1]) if flag == '--env')
            selected = Path(environment['TMPDIR'])
            self.assertTrue(selected.is_relative_to('/work'))
            disk_tmp = work / selected.relative_to('/work'); disk_tmp.mkdir()
            if shutil.disk_usage(disk_tmp).free < 2 << 30:
                self.skipTest('Fixture filesystem cannot satisfy the real recovery reserve')
            fixture = root / 'go-fixture'; fixture.mkdir()
            compiler_tmp = work / Path(environment['GOTMPDIR']).relative_to('/work'); compiler_tmp.mkdir()
            (fixture / 'go.mod').write_text('module example.com/guardian-temp-probe\ngo 1.26.0\n')
            (fixture / 'temp_test.go').write_text('''package reserveprobe
import("os";"path/filepath";"strings";"syscall";"testing")
func TestActualTempDirReserve(t *testing.T) {
 p:=t.TempDir()
 if !strings.HasPrefix(p,os.Getenv("EXPECTED_TEST_ROOT")+string(filepath.Separator)) { t.Fatalf("T.TempDir escaped GOTMPDIR: %s",p) }
 direct,err:=os.MkdirTemp("","direct-temp-probe");if err!=nil {t.Fatal(err)};defer os.RemoveAll(direct)
 if !strings.HasPrefix(direct,os.Getenv("EXPECTED_TMP_ROOT")+string(filepath.Separator)) {t.Fatalf("os.MkdirTemp escaped TMPDIR: %s",direct)}
 for _,path:=range []string{p,direct} {
  var space syscall.Statfs_t
  if err:=syscall.Statfs(path,&space);err!=nil {t.Fatal(err)}
  free:=uint64(space.Bavail)*uint64(space.Bsize)
  if free<2<<30 {t.Fatalf("insufficient free-space reserve for restore: %d",free)}
  t.Logf("actual T.TempDir/os.MkdirTemp=%s free=%d",path,free)
 }
}
''')
            env = dict(os.environ, TMPDIR=str(disk_tmp), EXPECTED_TMP_ROOT=str(disk_tmp),
                       EXPECTED_TEST_ROOT=str(compiler_tmp), GOTMPDIR=str(compiler_tmp),
                       GOTOOLCHAIN='local', GOPROXY='off', GOENV='off')
            result = subprocess.run([shutil.which('go'), 'test', '-v', '-count=1', '.'],
                cwd=fixture, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIn('actual T.TempDir/os.MkdirTemp=', result.stdout)

    def test_cleanup_removes_only_its_exact_labelled_container(self):
        calls = []
        token = "b" * 32
        name = "mg-app-build-" + token + "-offline"
        list_results = iter(["container-id\n", ""])
        def run(args, **kwargs):
            calls.append(args)
            if "ls" in args:
                return next(list_results)
            if "inspect" in args:
                return token + "\n"
            return ""
        with tempfile.TemporaryDirectory() as temporary, patch.object(builder, "_run", side_effect=run):
            builder._container("image", Path("/approved"), Path(temporary), "true", token, "offline", network="none")
        removals = [c for c in calls if "rm" in c]
        self.assertEqual(removals, [builder.DOCKER + ["rm", "--force", name]])

    def test_cleanup_never_removes_wrong_label_and_cannot_claim_success(self):
        calls = []
        def run(args, **kwargs):
            calls.append(args)
            if "ls" in args:
                return "some-id\n"
            if "inspect" in args:
                return "another-build-token\n"
            return ""
        with tempfile.TemporaryDirectory() as temporary, patch.object(builder, "_run", side_effect=run):
            with self.assertRaises(builder.BuildError):
                builder._container("image", Path("/approved"), Path(temporary), "true", "c" * 32, "offline", network="none")
        self.assertFalse(any("rm" in c for c in calls))

    def test_interrupted_docker_run_still_cleans_its_container_and_reports_failure(self):
        calls = []
        token = "d" * 32
        name = "mg-app-build-" + token + "-offline"
        list_results = iter(["still-running\n", ""])
        def run(args, **kwargs):
            calls.append(args)
            if "run" in args:
                raise builder.BuildError("timed out")
            if "ls" in args:
                return next(list_results)
            if "inspect" in args:
                return token
            return ""
        with tempfile.TemporaryDirectory() as temporary, patch.object(builder, "_run", side_effect=run):
            with self.assertRaisesRegex(builder.BuildError, "timed out"):
                builder._container("image", Path("/approved"), Path(temporary), "true", token, "offline", network="none")
        self.assertIn(builder.DOCKER + ["rm", "--force", name], calls)

    def test_unavailable_docker_cannot_be_treated_as_confirmed_cleanup(self):
        def run(args, **kwargs):
            if "ls" in args:
                raise builder.BuildError("daemon unavailable")
            return ""
        with tempfile.TemporaryDirectory() as temporary, patch.object(builder, "_run", side_effect=run):
            with self.assertRaisesRegex(builder.BuildError, "daemon unavailable"):
                builder._container("image", Path("/approved"), Path(temporary), "true", "e" * 32, "offline", network="none")


class HTTPSFetchTests(unittest.TestCase):
    def test_https_verification_and_header_separation_are_preserved(self):
        with patch.object(builder, "_run", return_value="{}\n200") as run:
            self.assertEqual(builder._fetch_text("https://example.com/", headers={"Authorization": "Bearer public-read-token"}), "{}")
        args = run.call_args.args[0]
        self.assertNotIn("--insecure", args)
        self.assertNotIn("-k", args)
        self.assertIn("--proto", args)
        self.assertIn("=https", args)
        self.assertIn("--location", args)
        self.assertEqual(args[args.index("--proto-redir") + 1], "=https")
        self.assertNotIn("Bearer public-read-token", " ".join(args))
        self.assertIn("Bearer public-read-token", run.call_args.kwargs["input_text"])

    def test_only_explicit_missing_module_responses_are_optional(self):
        with patch.object(builder, "_run", return_value="missing\n404"):
            self.assertIsNone(builder._fetch_text("https://example.com/", missing_ok=True))
            with self.assertRaises(builder.BuildError):
                builder._fetch_text("https://example.com/")
        with patch.object(builder, "_run", return_value="rate limited\n429"):
            with self.assertRaises(builder.BuildError):
                builder._fetch_text("https://example.com/", missing_ok=True)


class DiscoveryTests(unittest.TestCase):
    def test_retracted_approved_beta_is_not_silently_retained(self):
        root = "https://proxy.golang.org/example.com/imap/v2/@v/"
        responses = {root + "list": "v2.0.0-beta.8\nv2.0.0-beta.9\n",
                     root + "v2.0.0-beta.9.mod": "module example.com/imap/v2\nretract v2.0.0-beta.8\n"}
        with patch.object(builder, "_fetch_text", side_effect=lambda url, **kwargs: responses[url]):
            versions = builder._versions("example.com/imap/v2", current="v2.0.0-beta.8")
        self.assertIn("v2.0.0-beta.8", versions.retracted)
        with patch.object(builder, "_versions", return_value=versions):
            with self.assertRaisesRegex(builder.BuildError, "withdrawn"):
                builder.dependency_plan([{"Path": "example.com/imap/v2", "Version": "v2.0.0-beta.8"}])

    def test_tagless_module_checks_current_pseudo_against_effective_publisher_mod(self):
        pseudo = "v0.0.0-20241020182733-b788ff22d5a6"
        newer = "v0.0.0-20261020182733-a788ff22d5a6"
        with patch.object(builder, "_fetch_text", side_effect=["", "retract " + pseudo + "\n"]), \
             patch.object(builder, "_fetch_json", return_value={"Version": newer}):
            versions = builder._versions("example.com/sasl", current=pseudo)
        self.assertEqual(versions, [])
        self.assertIn(pseudo, versions.retracted)

    def test_retracted_stable_versions_are_not_candidates(self):
        responses = {"https://proxy.golang.org/example.com/a/@v/list": "v1.0.0\nv1.1.0\nv1.2.0\nv1.3.0\n",
                     "https://proxy.golang.org/example.com/a/@v/v1.3.0.mod": "module example.com/a\nretract (\nv1.3.0\n[v1.1.0,v1.2.0]\n)\n"}
        with patch.object(builder, "_fetch_text", side_effect=lambda url, **kwargs: responses[url]):
            versions = builder._versions("example.com/a")
        self.assertEqual(versions, ["v1.0.0"])
        self.assertEqual(versions.retracted, {"v1.1.0", "v1.2.0", "v1.3.0"})

    def test_withdrawn_current_pin_uses_qualified_nonwithdrawn_replacement(self):
        versions = builder._VersionList(["v1.0.0"], ["v1.1.0"])
        with patch.object(builder, "_versions", side_effect=lambda module, **kwargs: versions if module == "example.com/a" else []):
            plan = builder.dependency_plan([{"Path": "example.com/a", "Version": "v1.1.0"}])
        self.assertEqual(plan["modules"]["example.com/a"]["candidate"], "v1.0.0")
        self.assertIn("withdrew", plan["blockers"][0]["reason"])

    def test_sqlite_exact_pin_is_also_checked_for_publisher_withdrawal(self):
        def versions(module, **kwargs):
            if module == "modernc.org/sqlite":
                return ["v1.61.1"]
            if module == "modernc.org/libc":
                return builder._VersionList(["v1.79.1"], ["v1.79.0"])
            return []
        with patch.object(builder, "_versions", side_effect=versions), \
             patch.object(builder, "_fetch_text", return_value="require modernc.org/libc v1.79.0\n"):
            with self.assertRaisesRegex(builder.BuildError, "withdrawn"):
                builder.dependency_plan([{"Path": "modernc.org/sqlite", "Version": "v1.54.0"}])

    def test_required_module_404_fails_but_speculative_major_404_is_optional(self):
        with patch.object(builder, "_run", return_value="missing\n404"):
            with self.assertRaises(builder.BuildError):
                builder._versions("example.com/a")
            self.assertEqual(builder._versions("example.com/a/v2", missing_ok=True), [])

    def test_cheap_discovery_fingerprint_changes_on_new_vulnerability_database(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            (source / "go.mod").write_text("module example.com/app\nrequire (\n example.com/a v1.0.0 // indirect\n)\n")
            with patch.object(builder, "_compiler_and_image", return_value=("1.27.3", "docker.io/library/golang@sha256:" + "1" * 64)), \
                 patch.object(builder, "_versions", return_value=["v1.9.0"]), \
                 patch.object(builder, "dependency_plan", return_value={"modules": {}, "blockers": []}), \
                 patch.object(builder, "_fetch_json", return_value={"modified": "2026-10-27T21:16:18Z"}) as db:
                first = builder.discover(source)
                self.assertEqual(first["current_modules"], [{"Path": "example.com/a", "Version": "v1.0.0"}])
                self.assertEqual(builder.discover(source)["fingerprint"], first["fingerprint"])
                db.return_value = {"modified": "2026-10-31T22:00:00Z"}
                self.assertNotEqual(builder.discover(source)["fingerprint"], first["fingerprint"])


if __name__ == "__main__":
    unittest.main()
