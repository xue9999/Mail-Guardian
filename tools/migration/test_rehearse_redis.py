"""Private fixtures for restore orchestration; these never invoke Docker."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("rehearse_redis", Path(__file__).with_name("rehearse_redis.py"))
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)


class OrchestrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.rdb = self.root / "model.rdb"
        self.rdb.write_bytes(b"REDIS0012fixture")
        self.rdb.chmod(0o600)
        self.digest = hashlib.sha256(self.rdb.read_bytes()).hexdigest()
        self.report = self.root / "report.json"
        self.calls = []
        self.comparisons = 0
        self.fail_comparison = False
        self.fail_cleanup = False
        previous_umask = os.umask(0o077)
        self.addCleanup(os.umask, previous_umask)

    def docker(self, *args, **kwargs):
        self.calls.append(args)
        if args[0] == "inspect":
            if "NetworkSettings.Ports" in args[2]:
                port = "16379" if args[-1].endswith("reference") else "26379"
                return json.dumps({"6379/tcp": [{"HostIp": "127.0.0.1", "HostPort": port}]}).encode()
            if self.fail_cleanup and args[-1].endswith("reference"):
                raise RuntimeError("synthetic cleanup failure")
            return json.dumps({helper.LABEL: "a" * 32}).encode()
        if args[:2] == ("volume", "inspect"):
            return json.dumps({helper.LABEL: "a" * 32}).encode()
        return b""

    def compare(self, args, timeout=90):
        self.comparisons += 1
        self.assertEqual(args[1], "compare-redis")
        self.assertIn("--verified-no-additional-state", args)
        self.assertNotEqual(args[3], args[5])
        if self.fail_comparison:
            raise RuntimeError("synthetic comparison failure")
        return b'{"equivalent":true,"keys":2}'

    def invoke(self):
        argv = ["rehearse_redis.py", "--rdb", str(self.rdb), "--sha256", self.digest,
                "--recovery", "/root/guardian-recovery", "--report", str(self.report)]
        token = type("Token", (), {"hex": "a" * 32})()
        with patch.object(helper.uuid, "uuid4", return_value=token), \
                patch.object(helper, "docker", side_effect=self.docker), \
                patch.object(helper, "run", side_effect=self.compare), \
                patch.object(helper, "redis", side_effect=lambda name, *a: "PONG" if a == ("PING",) else "OK"), \
                patch.object(helper, "persistence_ready", return_value=True), \
                patch.object(helper.os, "geteuid", return_value=0), \
                patch.object(helper, "private_file"), \
                patch("sys.argv", argv):
            helper.main()

    def test_compares_before_conversion_after_conversion_and_normal_restart(self):
        self.invoke()
        report = json.loads(self.report.read_text())
        self.assertTrue(report["success"])
        self.assertTrue(report["aof_restart"])
        self.assertTrue(report["cleanup_complete"])
        self.assertFalse(report["retained_volumes"])
        self.assertEqual(self.comparisons, 3)
        self.assertEqual(hashlib.sha256(self.rdb.read_bytes()).hexdigest(), self.digest)
        preparations = [args[-1] for args in self.calls if args[0] == "run"]
        self.assertEqual(len(preparations), 2)
        for script in preparations:
            self.assertLess(script.index("redis-check-rdb"), script.index("chown redis:redis"))
        creates = [args for args in self.calls if args[0] == "create"]
        self.assertEqual(len(creates), 3)
        self.assertEqual(creates[-1][creates[-1].index("--appendonly") + 1], "yes")

    def test_failed_comparison_keeps_volumes_but_removes_containers(self):
        self.fail_comparison = True
        with self.assertRaisesRegex(RuntimeError, "comparison failure"):
            self.invoke()
        report = json.loads(self.report.read_text())
        self.assertFalse(report["success"])
        self.assertEqual(len(report["retained_volumes"]), 2)
        self.assertEqual(len([a for a in self.calls if a[:2] == ("rm", "--force")]), 2)
        self.assertFalse(any(a[:2] == ("volume", "rm") for a in self.calls))

    def test_cleanup_failure_still_attempts_other_container_and_writes_report(self):
        self.fail_cleanup = True
        with self.assertRaisesRegex(RuntimeError, "cleanup needs inspection"):
            self.invoke()
        report = json.loads(self.report.read_text())
        self.assertTrue(report["success"])
        self.assertFalse(report["cleanup_complete"])
        self.assertEqual(report["cleanup_errors"], 1)
        self.assertEqual(len(report["retained_volumes"]), 2)
        self.assertTrue(any(a[:2] == ("rm", "--force") and a[-1].endswith("target") for a in self.calls))


if __name__ == "__main__":
    unittest.main()
