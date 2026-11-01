import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import unittest
from unittest import mock

path = Path(__file__).with_name("docker_security_check.py")
spec = importlib.util.spec_from_file_location("docker_security_check", path)
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


def result(code=0, out="", err=""):
    return subprocess.CompletedProcess([], code, out, err)


class SecurityCheckTests(unittest.TestCase):
    def test_apt_retries_lock_but_not_permanent_errors(self):
        with mock.patch.object(check, "run", side_effect=[result(100, err="Could not get lock"), result()]) as run:
            with mock.patch.object(check.time, "sleep") as sleep:
                check.refresh_apt()
                self.assertEqual(run.call_count, 2)
                sleep.assert_called_once_with(20)
        with mock.patch.object(check, "run", return_value=result(100, err="repository signature invalid")) as run:
            with self.assertRaisesRegex(RuntimeError, "signature invalid"):
                check.refresh_apt()
            self.assertEqual(run.call_count, 1)

    def test_apt_lock_failure_is_bounded(self):
        with mock.patch.object(check, "run", return_value=result(100, err="Could not get lock")) as run:
            with mock.patch.object(check.time, "sleep"):
                with self.assertRaises(RuntimeError):
                    check.refresh_apt()
            self.assertEqual(run.call_count, 3)

    def test_package_update_detected(self):
        def fake_run(args, timeout=60):
            if args[0] == "dpkg-query":
                if args[-1] == "docker-ce":
                    return result(out="ii \t5:29.9.1")
                return result(1, err="no packages found matching")
            if args[0] == "apt-cache":
                return result(out="docker-ce:\n  Candidate: 5:29.9.2\n")
            if args[0] == "dpkg":
                self.assertEqual(args[-3:], ["5:29.9.2", "gt", "5:29.9.1"])
                return result()
            self.fail(str(args))
        with mock.patch.object(check, "run", side_effect=fake_run):
            self.assertTrue(check.package_candidates()[0]["update_available"])

    def test_no_candidate_is_a_failure(self):
        def fake_run(args, timeout=60):
            if args[0] == "dpkg-query":
                return result(out="ii \t1.0")
            return result(out="Candidate: (none)\n")
        with mock.patch.object(check, "run", side_effect=fake_run):
            with self.assertRaisesRegex(RuntimeError, "no candidate"):
                check.package_candidates()

    def test_image_drift_and_registry_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            compose = Path(directory) / "compose.yml"
            a = "sha256:" + "a" * 64
            b = "sha256:" + "b" * 64
            compose.write_text(f"services:\n  a:\n    image: registry/a:1@{a}\n  b:\n    image: registry/b:1@{a}\n")
            with mock.patch.object(check, "run", side_effect=[result(out=b), result(1, err="network unavailable")]):
                images, errors = check.image_candidates(compose)
            self.assertTrue(images[0]["digest_changed"])
            self.assertIn("network unavailable", errors[0])

    def test_unpinned_image_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            compose = Path(directory) / "compose.yml"
            compose.write_text("services:\n  a:\n    image: redis:latest\n")
            with self.assertRaisesRegex(RuntimeError, "not digest-pinned"):
                check.image_pins(compose)

    def test_swapped_compose_service_images_fail_closed(self):
        digest = "sha256:" + "a" * 64
        rendered = {"services": {
            "redis": {"image": "rspamd/rspamd:4.1.2@" + digest},
            "rspamd": {"image": "redis:7.4.9-alpine@" + digest},
            "unbound": {"image": "klutchell/unbound:1.25.2@" + digest}}}
        with mock.patch.object(check, "rendered_compose", return_value=rendered):
            with self.assertRaisesRegex(RuntimeError, "expected repository"):
                check.expected_service_images("/active/compose.yaml")

    def test_service_map_uses_real_render_subprocess_without_leaking_environment(self):
        digest = "sha256:" + "a" * 64
        with tempfile.TemporaryDirectory() as directory:
            compose = Path(directory) / "compose.yaml"
            config = {"services": {
                "redis": {"image": "redis:7.4.9-alpine@" + digest,
                          "environment": {"SENSITIVE_EXAMPLE": "do-not-report"}},
                "rspamd": {"image": "rspamd/rspamd:4.1.2@" + digest},
                "unbound": {"image": "klutchell/unbound:1.25.2@" + digest}}}
            executable = Path(directory) / "docker"
            expected_args = ["--host", "unix:///var/run/docker.sock", "compose", "--project-name",
                             "mail-guardian-pilot", "--project-directory", directory,
                             "--file", str(compose), "config", "--format", "json"]
            executable.write_text("#!/usr/bin/python3\nimport json,os,sys\n"
                                  "assert sys.argv[1:] == " + repr(expected_args) + "\n"
                                  "assert os.environ['GUARDIAN_RUNTIME_DIR'] == '/var/lib/mail-guardian-admin/pilot'\n"
                                  "print(json.dumps(" + repr(config) + "))\n")
            os.chmod(executable, 0o700)
            with mock.patch.dict(check.SAFE_ENV, {"PATH": directory}):
                services = check.expected_service_images(str(compose))
            self.assertEqual(services["redis"], "redis:7.4.9-alpine@" + digest)
            self.assertEqual(set(services), {"redis", "rspamd", "unbound"})
            self.assertNotIn("do-not-report", str(services))

    def test_compose_timeout_and_overflow_kill_the_plugin_process_group(self):
        for mode in ("timeout", "overflow"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                pid_file = Path(directory) / "pids"
                executable = Path(directory) / "docker"
                executable.write_text(
                    "#!/usr/bin/python3\nimport os,pathlib,subprocess,sys,time\n"
                    "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'])\n"
                    "pathlib.Path(" + repr(str(pid_file)) + ").write_text(str(os.getpid())+' '+str(child.pid))\n"
                    + ("os.write(1,b'X'*16384)\n" if mode == "overflow" else "") +
                    "time.sleep(60)\n")
                os.chmod(executable, 0o700)
                try:
                    with mock.patch.dict(check.SAFE_ENV, {"PATH": directory}), \
                            mock.patch.object(check, "COMPOSE_TIMEOUT", 1), \
                            mock.patch.object(check, "COMPOSE_OUTPUT_LIMIT", 4096):
                        with self.assertRaisesRegex(RuntimeError, "timed out|output limit"):
                            check.rendered_compose(str(Path(directory) / "compose.yml"))
                    self.assertTrue(pid_file.exists(), "fixture did not spawn its child")
                    parent, child = (int(value) for value in pid_file.read_text().split())
                    deadline = time.monotonic() + 3
                    while True:
                        states = [subprocess.run(["ps", "-o", "stat=", "-p", str(pid)],
                                  text=True, capture_output=True).stdout.strip() for pid in (parent, child)]
                        if all(not state or state.startswith("Z") for state in states):
                            break
                        if time.monotonic() >= deadline:
                            self.fail("Compose CLI or plugin child remained running")
                        time.sleep(0.05)
                finally:
                    if pid_file.exists():
                        try:
                            os.killpg(int(pid_file.read_text().split()[0]), signal.SIGKILL)
                        except ProcessLookupError:
                            pass

    def test_active_compose_drift_is_failure_but_active_images_are_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            active = Path(directory) / "active.yml"
            release = Path(directory) / "release.yml"
            active.write_text("active deployment\n")
            release.write_text("different release template\n")
            with mock.patch.object(check, "refresh_apt"), \
                    mock.patch.object(check, "package_candidates", return_value=[]), \
                    mock.patch.object(check, "image_candidates", return_value=([], [])) as images, \
                    mock.patch.object(check, "patch_candidates", return_value=([], [], False)), \
                    mock.patch.object(check, "expected_service_images", return_value={"rspamd": "expected"}), \
                    mock.patch.object(check, "rspamd_helper_image", return_value="expected"), \
                    mock.patch.object(check, "running_container_images", return_value=[{"matches_compose": True}]), \
                    mock.patch.object(sys, "argv", ["check", "--compose", str(active),
                                                   "--release-compose", str(release)]), \
                    mock.patch("builtins.print") as output:
                self.assertEqual(check.main(), 1)
            images.assert_called_once_with(str(active))
            report = json.loads(output.call_args.args[0])
            self.assertFalse(report["compose_matches_release"])
            self.assertIn("active Guardian compose differs from release template", report["errors"])

    def test_equal_compose_can_report_clean(self):
        with tempfile.TemporaryDirectory() as directory:
            active = Path(directory) / "active.yml"
            release = Path(directory) / "release.yml"
            active.write_text("same\n")
            release.write_text("same\n")
            with mock.patch.object(check, "refresh_apt"), \
                    mock.patch.object(check, "package_candidates", return_value=[]), \
                    mock.patch.object(check, "image_candidates", return_value=([], [])), \
                    mock.patch.object(check, "patch_candidates", return_value=([], [], False)), \
                    mock.patch.object(check, "expected_service_images", return_value={"rspamd": "expected"}), \
                    mock.patch.object(check, "rspamd_helper_image", return_value="expected"), \
                    mock.patch.object(check, "running_container_images", return_value=[{"matches_compose": True}]), \
                    mock.patch.object(sys, "argv", ["check", "--compose", str(active),
                                                   "--release-compose", str(release)]), \
                    mock.patch("builtins.print") as output:
                self.assertEqual(check.main(), 0)
            report = json.loads(output.call_args.args[0])
            self.assertTrue(report["compose_matches_release"])
            self.assertEqual(report["errors"], [])

    def test_compose_change_during_check_is_not_clean(self):
        with tempfile.TemporaryDirectory() as directory:
            active = Path(directory) / "active.yml"
            release = Path(directory) / "release.yml"
            active.write_text("same\n")
            release.write_text("same\n")
            def changing_discovery(*args):
                active.write_text("updated during check\n")
                return [], [], False
            with mock.patch.object(check, "refresh_apt"), \
                    mock.patch.object(check, "package_candidates", return_value=[]), \
                    mock.patch.object(check, "image_candidates", return_value=([], [])), \
                    mock.patch.object(check, "patch_candidates", side_effect=changing_discovery), \
                    mock.patch.object(check, "expected_service_images", return_value={"rspamd": "expected"}), \
                    mock.patch.object(check, "rspamd_helper_image", return_value="expected"), \
                    mock.patch.object(check, "running_container_images", return_value=[{"matches_compose": True}]), \
                    mock.patch.object(sys, "argv", ["check", "--compose", str(active),
                                                   "--release-compose", str(release)]), \
                    mock.patch("builtins.print") as output:
                self.assertEqual(check.main(), 1)
            report = json.loads(output.call_args.args[0])
            self.assertIn("active Compose changed during the check", report["errors"])

    def test_rspamd_helper_mismatch_is_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            compose = Path(directory) / "compose.yml"
            compose.write_text("same\n")
            with mock.patch.object(check, "refresh_apt"), \
                    mock.patch.object(check, "package_candidates", return_value=[]), \
                    mock.patch.object(check, "image_candidates", return_value=([], [])), \
                    mock.patch.object(check, "patch_candidates", return_value=([], [], False)), \
                    mock.patch.object(check, "expected_service_images", return_value={"rspamd": "updated"}), \
                    mock.patch.object(check, "rspamd_helper_image", return_value="old"), \
                    mock.patch.object(check, "running_container_images", return_value=[{"matches_compose": True}]), \
                    mock.patch.object(sys, "argv", ["check", "--compose", str(compose),
                                                   "--release-compose", str(compose)]), \
                    mock.patch("builtins.print") as output:
                self.assertEqual(check.main(), 1)
            report = json.loads(output.call_args.args[0])
            self.assertFalse(report["rspamd_helper_matches_compose"])
            self.assertIn("maintenance helper Rspamd image differs from active Compose", report["errors"])

    def test_inspects_container_image_even_when_stopped(self):
        expected = {"redis": "redis:expected", "rspamd": "rspamd:expected", "unbound": "unbound:expected"}
        identities = "aaaaaaaaaaaa\nbbbbbbbbbbbb\ncccccccccccc\n"
        rows = '\n'.join(json.dumps(service) + '\t' + json.dumps(image) + '\t' + json.dumps(state)
                         for service, image, state in [("redis", "redis:expected", "exited"),
                                                       ("rspamd", "rspamd:old", "running"),
                                                       ("unbound", "unbound:expected", "running")])
        with mock.patch.object(check, "run", side_effect=[result(out=identities), result(out=rows)]) as run:
            containers = check.running_container_images(expected)
        self.assertIn("--all", run.call_args_list[0].args[0])
        by_service = {item["service"]: item for item in containers}
        self.assertEqual(by_service["redis"]["status"], "exited")
        self.assertTrue(by_service["redis"]["matches_compose"])
        self.assertFalse(by_service["rspamd"]["matches_compose"])

    def test_runtime_image_mismatch_is_reported_as_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            compose = Path(directory) / "compose.yml"
            compose.write_text("same\n")
            with mock.patch.object(check, "refresh_apt"), \
                    mock.patch.object(check, "package_candidates", return_value=[]), \
                    mock.patch.object(check, "image_candidates", return_value=([], [])), \
                    mock.patch.object(check, "patch_candidates", return_value=([], [], False)), \
                    mock.patch.object(check, "expected_service_images", return_value={"rspamd": "expected"}), \
                    mock.patch.object(check, "rspamd_helper_image", return_value="expected"), \
                    mock.patch.object(check, "running_container_images", return_value=[{"matches_compose": False}]), \
                    mock.patch.object(sys, "argv", ["check", "--compose", str(compose),
                                                   "--release-compose", str(compose)]), \
                    mock.patch("builtins.print") as output:
                self.assertEqual(check.main(), 1)
            report = json.loads(output.call_args.args[0])
            self.assertFalse(report["runtime_images_match_compose"])
            self.assertIn("Guardian container image differs from active Compose", report["errors"])

    def test_missing_containers_is_not_clean(self):
        with mock.patch.object(check, "run", return_value=result(out="")):
            with self.assertRaisesRegex(RuntimeError, "not present"):
                check.running_container_images({"redis": "x"})

    def test_helper_pin_is_read_as_data_and_requires_literal(self):
        with tempfile.TemporaryDirectory() as directory:
            helper = Path(directory) / "helper.py"
            helper.write_text('RSPAMD_IMAGE = "rspamd:expected"\nraise Exception("must not run")\n')
            self.assertEqual(check.rspamd_helper_image(helper), "rspamd:expected")
            helper.write_text('RSPAMD_IMAGE = dangerous()\n')
            with self.assertRaisesRegex(RuntimeError, "could not read"):
                check.rspamd_helper_image(helper)

    def test_new_patch_candidate_is_reported_with_real_helper_process(self):
        # Exercise the helper protocol and exit status together, while avoiding
        # network access and any live service or system package changes.
        with tempfile.TemporaryDirectory() as directory:
            compose = Path(directory) / "compose.yml"
            compose.write_text("unchanged\n")
            helper = Path(directory) / "candidate_finder.py"
            helper.write_text("import json,sys\n"
                              "assert sys.argv[1:] == ['--compose', " + repr(str(compose)) + "]\n"
                              "print(json.dumps({'mode':'discovery_only', 'images': "
                              "[{'repo':'redis','installed_tag':'7.4.9-alpine',"
                              "'candidate':{'tag':'7.4.12-alpine'}}, "
                              "{'repo':'rspamd/rspamd','candidate':None}, "
                              "{'repo':'klutchell/unbound','candidate':None}], "
                              "'errors':[], 'attention':True}))\n"
                              "sys.exit(2)\n")
            with mock.patch.object(check, "refresh_apt"), \
                    mock.patch.object(check, "package_candidates", return_value=[]), \
                    mock.patch.object(check, "image_candidates", return_value=([], [])), \
                    mock.patch.object(check, "expected_service_images", return_value={"rspamd": "expected"}), \
                    mock.patch.object(check, "rspamd_helper_image", return_value="expected"), \
                    mock.patch.object(check, "running_container_images", return_value=[{"matches_compose": True}]), \
                    mock.patch.object(sys, "argv", ["check", "--compose", str(compose),
                        "--release-compose", str(compose), "--candidate-tool", str(helper)]), \
                    mock.patch("builtins.print") as output:
                self.assertEqual(check.main(), 2)
            report = json.loads(output.call_args.args[0])
            self.assertTrue(report["attention"])
            self.assertEqual(report["patch_candidates"][0]["candidate"]["tag"], "7.4.12-alpine")
            self.assertEqual(report["errors"], [])

    def test_patch_discovery_error_cannot_report_clean(self):
        with tempfile.TemporaryDirectory() as directory:
            compose = Path(directory) / "compose.yml"
            compose.write_text("unchanged\n")
            with mock.patch.object(check, "refresh_apt"), \
                    mock.patch.object(check, "package_candidates", return_value=[]), \
                    mock.patch.object(check, "image_candidates", return_value=([], [])), \
                    mock.patch.object(check, "patch_candidates", side_effect=RuntimeError("registry unavailable")), \
                    mock.patch.object(check, "expected_service_images", return_value={"rspamd": "expected"}), \
                    mock.patch.object(check, "rspamd_helper_image", return_value="expected"), \
                    mock.patch.object(check, "running_container_images", return_value=[{"matches_compose": True}]), \
                    mock.patch.object(sys, "argv", ["check", "--compose", str(compose),
                                                   "--release-compose", str(compose)]), \
                    mock.patch("builtins.print") as output:
                self.assertEqual(check.main(), 1)
            report = json.loads(output.call_args.args[0])
            self.assertIn("patch discovery failed: registry unavailable", report["errors"])

    def test_patch_discovery_rejects_inconsistent_exit(self):
        body = json.dumps({"mode": "discovery_only", "images": [
            {"repo": "redis", "candidate": {"tag": "7.4.12-alpine"}},
            {"repo": "rspamd/rspamd", "candidate": None},
            {"repo": "klutchell/unbound", "candidate": None}], "errors": [], "attention": True})
        with mock.patch.object(check, "run", return_value=result(0, out=body)):
            with self.assertRaisesRegex(RuntimeError, "exited inconsistently"):
                check.patch_candidates("/active.yml", "/finder")

    def test_partial_failure_does_not_hide_other_findings(self):
        with mock.patch.object(check, "refresh_apt", side_effect=RuntimeError("offline")):
            with mock.patch.object(check, "image_candidates", return_value=([{"digest_changed": True}], [])):
                with mock.patch.object(check, "patch_candidates", return_value=([], [], False)):
                    with mock.patch.object(sys, "argv", ["check"]):
                        with mock.patch("builtins.print") as output:
                            self.assertEqual(check.main(), 1)
                            self.assertIn('"attention": true', output.call_args.args[0])
                            self.assertIn("offline", output.call_args.args[0])


import sys

if __name__ == "__main__":
    unittest.main()
