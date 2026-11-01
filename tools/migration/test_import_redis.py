"""First-volume model import orchestration fixtures; no Docker or live files."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("import_redis", Path(__file__).with_name("import_redis.py"))
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)


class ImportTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.rdb = self.root / "model.rdb"
        self.rdb.write_bytes(b"REDIS0012fixture")
        self.digest = hashlib.sha256(self.rdb.read_bytes()).hexdigest()
        self.report = self.root / "import.json"
        self.calls = []
        self.comparisons = 0
        self.fail_comparison = False
        self.token = "a" * 32

    def docker(self, *args):
        self.calls.append(args)
        if args[0] == "inspect":
            if "NetworkSettings.Ports" in args[2]:
                port = "16379" if args[-1].endswith("reference") else "26379"
                return json.dumps({"6379/tcp": [{"HostIp": "127.0.0.1", "HostPort": port}]}).encode()
            return json.dumps({helper.LABEL: self.token}).encode()
        if args[:2] == ("volume", "inspect"):
            return json.dumps({helper.LABEL: self.token}).encode()
        return b""

    def compare(self, args, timeout=120):
        self.comparisons += 1
        self.assertEqual(args[1], "compare-redis")
        self.assertIn("--verified-no-additional-state", args)
        if self.fail_comparison:
            raise RuntimeError("synthetic comparison failure")
        return b'{"equivalent":true,"keys":2}'

    def invoke(self):
        token = type("Token", (), {"hex": self.token})()
        with patch.object(helper.uuid, "uuid4", return_value=token), \
                patch.object(helper, "docker", side_effect=self.docker), \
                patch.object(helper, "run", side_effect=self.compare), \
                patch.object(helper, "redis", side_effect=lambda name, *a: "PONG" if a == ("PING",) else "OK"), \
                patch.object(helper, "persistence_ready", return_value=True):
            return helper.import_model(self.rdb, self.digest, Path("/root/release"), "b" * 64, self.report)

    def test_verified_volume_survives_normal_config_restart_and_cleanup(self):
        report = self.invoke()
        self.assertTrue(report["success"])
        self.assertTrue(report["normal_config_aof_restart"])
        self.assertTrue(report["migration_pending_preserved"])
        self.assertEqual(report["retained_volumes"], [helper.TARGET])
        self.assertEqual(self.comparisons, 3)
        self.assertEqual(hashlib.sha256(self.rdb.read_bytes()).hexdigest(), self.digest)
        creates = [args for args in self.calls if args[0] == "create"]
        self.assertEqual(len(creates), 3)
        self.assertNotIn("--appendonly", creates[-1])
        self.assertEqual(creates[-1][-1], "/usr/local/etc/redis/redis.conf")
        production = [args for args in self.calls if args[:2] == ("volume", "create") and args[-1] == helper.TARGET]
        self.assertEqual(len(production), 1)
        self.assertIn("com.docker.compose.project=mail-guardian-pilot", production[0])
        self.assertIn("com.docker.compose.volume=redis_data", production[0])
        self.assertFalse(any(args[:2] == ("volume", "rm") and args[-1] == helper.TARGET for args in self.calls))

    def test_failed_comparison_never_removes_either_model_volume(self):
        self.fail_comparison = True
        with self.assertRaisesRegex(RuntimeError, "comparison failure"):
            self.invoke()
        report = json.loads(self.report.read_text())
        self.assertFalse(report["success"])
        self.assertEqual(len(report["retained_volumes"]), 2)
        self.assertFalse(any(args[:2] == ("volume", "rm") for args in self.calls))
        self.assertEqual(len([args for args in self.calls if args[0] == "stop"]), 2)

    def test_existing_production_volume_is_refused_before_creation(self):
        def state(args, timeout=120):
            if "--property=UnitFileState" in args:
                return b"disabled\n"
            return b"inactive\n"

        def docker(*args):
            if args[:2] == ("volume", "ls"):
                return (helper.TARGET + "\n").encode()
            self.assertEqual(args[0], "ps")
            return b""

        with patch.object(helper, "run", side_effect=state), patch.object(helper, "docker", side_effect=docker):
            with self.assertRaisesRegex(ValueError, "already exists"):
                helper.require_quiescent()

    def test_enabled_timer_is_refused_before_docker_access(self):
        def state(args, timeout=120):
            if "--property=UnitFileState" in args:
                return b"enabled\n"
            return b"inactive\n"

        with patch.object(helper, "run", side_effect=state), \
                patch.object(helper, "docker", side_effect=AssertionError("must not touch Docker")):
            with self.assertRaisesRegex(ValueError, "disabled"):
                helper.require_quiescent()


if __name__ == "__main__":
    unittest.main()
