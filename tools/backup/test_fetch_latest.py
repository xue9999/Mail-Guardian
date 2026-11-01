import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("guardian_fetch", Path(__file__).with_name("fetch_latest.py"))
fetch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fetch)


class FetchTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="guardian-encrypted-fetch-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.payload = b"age-encryption.org/v1\nsynthetic encrypted bytes"
        self.row = {"name": "20261031T010203.123456Z.age", "bytes": len(self.payload),
                    "sha256": hashlib.sha256(self.payload).hexdigest()}

    def stream(self, payload=None, row=None):
        return io.BytesIO(json.dumps(row or self.row).encode() + b"\n" +
                          (self.payload if payload is None else payload))

    def test_verified_download_publishes_once_and_retains_matching_copy(self):
        row, path = fetch.receive(self.stream(), self.root)
        fetch.publish(row, path, self.root)
        retained = self.root / self.row["name"]
        inode = retained.stat().st_ino
        self.assertEqual(retained.read_bytes(), self.payload)
        self.assertEqual(retained.stat().st_mode & 0o777, 0o600)
        row, path = fetch.receive(self.stream(), self.root)
        fetch.publish(row, path, self.root)
        self.assertEqual(retained.stat().st_ino, inode)
        self.assertEqual(len(list(self.root.iterdir())), 2)

    def test_truncated_or_bad_digest_leaves_no_files(self):
        for body in (self.payload[:-1], b"x" * len(self.payload), self.payload + b"excess"):
            with self.assertRaises(ValueError):
                fetch.receive(self.stream(body), self.root)
            self.assertEqual(list(self.root.iterdir()), [])

    def test_existing_different_copy_is_never_overwritten(self):
        retained = self.root / self.row["name"]
        retained.write_bytes(b"preserve original")
        retained.chmod(0o600)
        row, path = fetch.receive(self.stream(), self.root)
        with self.assertRaises(ValueError):
            fetch.publish(row, path, self.root)
        self.assertEqual(retained.read_bytes(), b"preserve original")

    def test_metadata_rejects_traversal_and_excessive_size(self):
        for row in (dict(self.row, name="../outside.age"),
                    dict(self.row, bytes=fetch.MAX_BUNDLE + 1),
                    dict(self.row, bytes=True), dict(self.row, sha256="bad")):
            with self.assertRaises(ValueError):
                fetch.metadata(json.dumps(row))

    def test_destination_symlink_is_rejected(self):
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            fetch.private_directory(alias)

    def test_remote_program_compiles_and_contains_no_private_state_paths(self):
        compile(fetch.REMOTE.replace("__INSTANCE__", "pilot"), "remote-backup-read", "exec")
        self.assertNotIn("/etc/mail-guardian", fetch.REMOTE)
        self.assertNotIn("/var/lib/mail-guardian", fetch.REMOTE)
        self.assertNotIn("archive-identity", fetch.REMOTE)


if __name__ == "__main__":
    unittest.main()
