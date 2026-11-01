#!/usr/bin/env python3
"""Read-only preflight policy tests using disposable metadata and commands."""

import contextlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("guardian_host_check", Path(__file__).with_name("check_host.py"))
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)

DOCKER = {"server_version": "29.0.0", "cgroup_version": "2",
          "security_options": ["name=seccomp,profile=builtin", "name=cgroupns"],
          "docker_root_dir": "/var/lib/docker"}


class HostFixture:
    def __init__(self, release="26.04"):
        self.release = release
        self.machine = "x86_64"
        self.id = "ubuntu"
        self.cpu_count = 2
        self.memory_kib = 3900000
        self.clock = b"yes\n"
        self.v3 = b"  x86-64-v3 (supported, searched)\n"
        self.docker = dict(DOCKER)
        self.engine_unavailable = False
        self.kernel = b"ordinary warning\n"
        self.kernel_unavailable = False
        self.free_bytes = 20 << 30
        self.read_only = False
        self.devices = {path: 1 for path in host.STORAGE_PATHS}
        self.systemd = b"systemd 259 (259.5-1ubuntu1)\n"
        self.compose = b"5.0.0\n"
        self.compose_help = b"Options:\n      --wait Wait for services to be running or healthy\n"
        self.booted = "systemd\n"
        self.commands = []

    def read(self, path, *args, **kwargs):
        return {"/etc/os-release": 'ID="' + self.id + '"\nVERSION_ID="' + self.release + '"\n',
                "/proc/1/comm": self.booted,
                "/proc/meminfo": "MemTotal: " + str(self.memory_kib) + " kB\n"}[str(path)]

    def run(self, args, **kwargs):
        self.commands.append(args)
        if args == ["/usr/bin/systemctl", "--version"]:
            return self.systemd
        if args == ["/lib64/ld-linux-x86-64.so.2", "--help"]:
            return self.v3
        if args == ["/usr/sbin/visudo", "-c"]:
            return b"/etc/sudoers: parsed OK\n"
        if args[:5] == ["/usr/bin/docker", "--host", host.DOCKER_HOST, "info", "--format"]:
            if self.engine_unavailable:
                raise host.CheckError("private dependency failure must not appear")
            return json.dumps(self.docker).encode()
        if args == ["/usr/bin/docker", "--host", host.DOCKER_HOST, "compose", "version", "--short"]:
            return self.compose
        if args == ["/usr/bin/docker", "--host", host.DOCKER_HOST, "compose", "up", "--help"]:
            return self.compose_help
        if args == ["/usr/bin/dmesg", "--level=err,warn", "--notime"]:
            if self.kernel_unavailable:
                raise host.CheckError("private kernel failure must not appear")
            return self.kernel
        if args == ["/usr/bin/timedatectl", "show", "--property=NTPSynchronized", "--value"]:
            if self.clock is None:
                raise host.CheckError("private clock failure must not appear")
            return self.clock
        raise AssertionError("Unexpected command: " + repr(args))

    def storage(self, target):
        return {"path": str(target), "existing_ancestor": "/var/lib", "free_bytes": self.free_bytes,
                "total_bytes": 40 << 30, "st_dev": self.devices[str(target)], "read_only": self.read_only}

    def collect(self):
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(host, "read_text", side_effect=self.read))
            stack.enter_context(patch.object(host, "run", side_effect=self.run))
            stack.enter_context(patch.object(host, "storage_sample", side_effect=self.storage))
            stack.enter_context(patch.object(host.os, "geteuid", return_value=0))
            stack.enter_context(patch.object(host, "executable", return_value=True))
            stack.enter_context(patch.object(host.os, "cpu_count", return_value=self.cpu_count))
            stack.enter_context(patch.object(host.platform, "machine", return_value=self.machine))
            return host.collect()


def status(report, name):
    return next(item["status"] for item in report["checks"] if item["name"] == name)


class PrerequisiteTests(unittest.TestCase):
    def test_qualified_platforms_and_read_only_command_set(self):
        for release in ("24.04", "26.04", "26.10"):
            with self.subTest(release=release):
                fixture = HostFixture(release)
                report = fixture.collect()
                self.assertTrue(report["ready"])
                self.assertFalse(any(item["status"] != "pass" for item in report["checks"]))
                self.assertEqual(report["resources"]["docker"]["docker_root_dir"], "/var/lib/docker")
                self.assertEqual(report["resources"]["compose_version"], "5.0.0")
                self.assertEqual({item["path"] for item in report["resources"]["storage"]}, set(host.STORAGE_PATHS))
                for argv in fixture.commands:
                    self.assertFalse(set(argv) & {"start", "stop", "restart", "pull", "run", "exec", "enable", "install"})
                    if "up" in argv:
                        self.assertEqual(argv[-2:], ["up", "--help"])
                    if argv[0] == "/usr/bin/docker":
                        self.assertEqual(argv[1:3], ["--host", "unix:///var/run/docker.sock"])
                self.assertEqual("x86_64_v3" in report["resources"], release in ("26.04", "26.10"))

    def test_unsupported_platform_and_missing_metadata_fail(self):
        for release, distro, machine in (("27.04", "ubuntu", "x86_64"), ("26.04", "debian", "x86_64"),
                                        ("26.04", "ubuntu", "aarch64"), ("", "ubuntu", "x86_64")):
            with self.subTest(release=release, distro=distro, machine=machine):
                fixture = HostFixture(release)
                fixture.id, fixture.machine = distro, machine
                report = fixture.collect()
                self.assertFalse(report["ready"])
                self.assertEqual(status(report, "platform"), "fail")
        with patch.object(host, "read_text", return_value='ID=ubuntu\nID=debian\nVERSION_ID="26.04"\n'):
            with self.assertRaises(host.CheckError):
                host.read_release()

    def test_newer_ubuntu_requires_supported_guest_v3_not_just_listed_v3(self):
        for release in ("26.04", "26.10"):
            fixture = HostFixture(release)
            for output in (b"  x86-64-v3\n  x86-64-v2 (supported, searched)\n", b"", b"x86-64-v3 (not supported)\n"):
                with self.subTest(release=release, output=output):
                    fixture.v3 = output
                    report = fixture.collect()
                    self.assertEqual(status(report, "cpu_baseline"), "fail")
                    self.assertFalse(report["ready"])

    def test_old_dependencies_and_unbooted_service_manager_fail(self):
        for attribute, value, name in (("systemd", b"systemd 248\n", "systemd"),
                                       ("systemd", b"unrecognized\n", "systemd"),
                                       ("compose", b"1.29.2\n", "compose"),
                                       ("compose_help", b"Options:\n      --wait-timeout int\n", "compose"),
                                       ("booted", "bash\n", "service_manager")):
            with self.subTest(attribute=attribute, value=value):
                fixture = HostFixture()
                setattr(fixture, attribute, value)
                report = fixture.collect()
                self.assertFalse(report["ready"])
                self.assertEqual(status(report, name), "fail")

    def test_docker_policy_rejects_insecure_or_unqualified_daemons(self):
        for changes in ({"server_version": "27.5.1"}, {"cgroup_version": "1"},
                        {"security_options": ["name=rootless"]}, {"security_options": ["name=userns"]}, {"docker_root_dir": "/home/user/docker"},
                        {"security_options": None}, {"server_version": "private unrecognized version"}):
            with self.subTest(changes=changes), self.assertRaises(host.CheckError):
                host.docker_fields(json.dumps(dict(DOCKER, **changes)))
        for output in (b"{}", b"[]", b"not json"):
            with self.subTest(output=output), self.assertRaises(host.CheckError):
                host.docker_fields(output)

    def test_unavailable_dependency_and_kernel_errors_never_report_success_or_raw_details(self):
        fixture = HostFixture()
        fixture.engine_unavailable = True
        fixture.kernel = b"private-mail-content\nI/O error, dev vda\n"
        report = fixture.collect()
        self.assertEqual(status(report, "docker"), "fail")
        self.assertEqual(status(report, "kernel_storage"), "fail")
        self.assertFalse(report["ready"])
        self.assertNotIn("private", json.dumps(report))
        fixture.kernel_unavailable = True
        report = fixture.collect()
        self.assertEqual(status(report, "kernel_storage"), "fail")
        self.assertNotIn("private", json.dumps(report))

    def test_two_gib_storage_floor_and_read_only_rejection(self):
        fixture = HostFixture()
        fixture.free_bytes = host.MIN_FREE_BYTES
        self.assertTrue(fixture.collect()["ready"])
        fixture.free_bytes -= 1
        report = fixture.collect()
        self.assertFalse(report["ready"])
        self.assertTrue(all(status(report, "storage:" + path) == "fail" for path in host.STORAGE_PATHS))
        fixture.free_bytes = 20 << 30
        fixture.read_only = True
        self.assertFalse(fixture.collect()["ready"])

    def test_separate_containerd_filesystem_requires_runtime_gate_coverage(self):
        fixture = HostFixture()
        fixture.devices["/var/lib/containerd"] = 2
        report = fixture.collect()
        self.assertFalse(report["ready"])
        self.assertEqual(status(report, "containerd_storage"), "fail")
        fixture.devices["/var/lib/mail-guardian"] = 2
        report = fixture.collect()
        self.assertTrue(report["ready"])
        self.assertEqual(status(report, "containerd_storage"), "pass")

    def test_resource_warnings_are_advisory_but_clock_must_be_confirmed(self):
        fixture = HostFixture()
        fixture.cpu_count = 1
        fixture.memory_kib = 2 << 20
        report = fixture.collect()
        self.assertTrue(report["ready"])
        self.assertEqual(status(report, "cpu_capacity"), "warn")
        self.assertEqual(status(report, "memory_capacity"), "warn")
        for clock in (b"no\n", None, b"invalid\n"):
            fixture.clock = clock
            report = fixture.collect()
            self.assertFalse(report["ready"])
            self.assertEqual(status(report, "cpu_capacity"), "warn")
            self.assertEqual(status(report, "memory_capacity"), "warn")
            self.assertEqual(status(report, "clock"), "fail")
            self.assertFalse(report["resources"].get("clock_synchronized", False))
        fixture.cpu_count = None
        fixture.memory_kib = 0
        report = fixture.collect()
        self.assertFalse(report["ready"])
        self.assertEqual(status(report, "cpu_capacity"), "fail")
        self.assertEqual(status(report, "memory_capacity"), "fail")


class StorageTests(unittest.TestCase):
    def metadata(self, path):
        if str(path) in ("/var/lib/containerd",):
            raise FileNotFoundError()
        return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_dev=17)

    def test_missing_store_uses_existing_ancestor_without_creating_directory(self):
        filesystem = SimpleNamespace(f_bavail=100, f_frsize=4096, f_blocks=200, f_flag=0)
        with patch.object(Path, "lstat", lambda path: self.metadata(path)), patch.object(host.os, "statvfs", return_value=filesystem) as statvfs:
            sample = host.storage_sample("/var/lib/containerd")
        self.assertEqual(sample["existing_ancestor"], "/var/lib")
        self.assertEqual(sample["free_bytes"], 409600)
        self.assertEqual(sample["st_dev"], 17)
        statvfs.assert_called_once_with(Path("/var/lib"))

    def test_symlink_or_untrusted_ancestor_is_rejected(self):
        for mode, uid in ((stat.S_IFLNK | 0o777, 0), (stat.S_IFDIR | 0o777, 0), (stat.S_IFDIR | 0o755, 1000)):
            with self.subTest(mode=mode, uid=uid):
                def metadata(path):
                    if str(path) == "/var/lib/containerd":
                        return SimpleNamespace(st_mode=mode, st_uid=uid, st_dev=17)
                    return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_dev=17)
                with patch.object(Path, "lstat", metadata), self.assertRaises(host.CheckError):
                    host.storage_sample("/var/lib/containerd")


class ExecutableTests(unittest.TestCase):
    def test_regular_executable_targets_required_including_alternatives(self):
        with patch.object(host.os, "stat", return_value=SimpleNamespace(st_mode=stat.S_IFREG | 0o755)), \
             patch.object(host.os, "access", return_value=True):
            self.assertTrue(host.executable("/usr/bin/sudo"))
        with patch.object(host.os, "stat", return_value=SimpleNamespace(st_mode=stat.S_IFDIR | 0o755)), \
             patch.object(host.os, "access", return_value=True):
            self.assertFalse(host.executable("/usr/bin/sudo"))
        with patch.object(host.os, "stat", side_effect=FileNotFoundError()):
            self.assertFalse(host.executable("/usr/bin/sudo"))


class BoundedCommandTests(unittest.TestCase):
    def test_clean_environment_and_no_raw_dependency_errors(self):
        with patch.dict(os.environ, {"DOCKER_HOST": "private-remote-daemon", "HTTP_PROXY": "private-proxy"}):
            output = host.run([sys.executable, "-c", "import os; print(os.getenv('DOCKER_HOST', 'clean')); print(os.getenv('HTTP_PROXY', 'clean'))"])
        self.assertEqual(output, b"clean\nclean\n")
        with self.assertRaises(host.CheckError) as error:
            host.run([sys.executable, "-c", "import sys; print('private-detail',file=sys.stderr); sys.exit(1)"])
        self.assertNotIn("private", str(error.exception))

    def test_deadline_and_output_limits(self):
        with self.assertRaisesRegex(host.CheckError, "timed out"):
            host.run([sys.executable, "-c", "import time; time.sleep(2)"], timeout=0.05)
        for stream in ("stdout", "stderr"):
            with self.subTest(stream=stream), self.assertRaisesRegex(host.CheckError, "limit"):
                host.run([sys.executable, "-c", "import sys; sys." + stream + ".write('x'*1000000)"], max_output=100)

    @unittest.skipUnless(hasattr(os, "fork"), "requires POSIX process groups")
    def test_timeout_kills_descendant_even_after_direct_child_exits(self):
        original_popen, original_killpg = subprocess.Popen, os.killpg
        spawned, killed = [], []

        def spawn(*args, **kwargs):
            proc = original_popen(*args, **kwargs)
            spawned.append(proc)
            return proc

        def kill_group(pid, sig):
            killed.append((pid, sig, spawned[0].poll()))
            return original_killpg(pid, sig)

        # The direct child exits successfully; its descendant keeps both pipes
        # open. A timeout must kill that remaining group instead of leaking it.
        code = "import os,time; pid=os.fork(); os._exit(0) if pid else time.sleep(10)"
        try:
            with patch.object(host.subprocess, "Popen", side_effect=spawn), \
                 patch.object(host.os, "killpg", side_effect=kill_group), \
                 self.assertRaisesRegex(host.CheckError, "timed out"):
                host.run([sys.executable, "-c", code], timeout=2)
            self.assertEqual(len(killed), 1)
            self.assertEqual(killed[0][2], 0, "the direct child must already have exited")
        finally:
            if spawned and not killed:
                try:
                    original_killpg(spawned[0].pid, host.signal.SIGKILL)
                except ProcessLookupError:
                    pass


if __name__ == "__main__":
    unittest.main()
