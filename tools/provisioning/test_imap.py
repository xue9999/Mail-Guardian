#!/usr/bin/env python3
"""Credential boundary tests; no mailbox, SSH or actual passwords are used."""

import contextlib
import importlib.util
import io
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("guardian_provision_imap", Path(__file__).with_name("imap.py"))
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
remote = {"__name__": "fixture"}
exec(compile(helper.REMOTE_PROGRAM, "imap-remote-fixture", "exec"), remote)
SECRET = "fixture-ąpp-pa55word"


class IMAPProvisionTests(unittest.TestCase):
    def fixture(self):
        temp = tempfile.TemporaryDirectory(prefix=".guardian-imap-test-", dir=Path.home())
        self.addCleanup(temp.cleanup)
        root = Path(temp.name).resolve()
        directory = root / "credentials"
        directory.mkdir(mode=0o700)
        return root, directory

    def publish(self, directory, payload=None):
        raw = (SECRET + "\n").encode() if payload is None else payload
        remote["publish_secret"](raw, str(directory), os.geteuid())

    def test_local_and_remote_validation_accept_same_secret_bytes(self):
        for secret in (SECRET, "a", "x" * 1024, " ", "zażółć"):
            raw = (secret + "\n").encode()
            self.assertEqual(helper.validate_password(secret), secret)
            self.assertEqual(remote["validate_input"](raw), raw)
        for secret in ("", "x" * 1025, "ą" * 513, "bad\ninput", "bad\r", "bad\x00", "bad\t", "bad\x7f", "bad\u0085", "bad\ud800"):
            with self.subTest(length=len(secret)):
                with self.assertRaises(helper.ProvisionError):
                    helper.validate_password(secret)
                try:
                    raw = (secret + "\n").encode()
                except UnicodeError:
                    raw = b"\xff\n"
                with self.assertRaises((ValueError, UnicodeError)):
                    remote["validate_input"](raw)

    def test_default_preview_never_prompts_or_connects(self):
        with patch.object(helper, "prompt_password", side_effect=AssertionError()), patch.object(helper, "send_secret", side_effect=AssertionError()):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(helper.main([]), 0)
        self.assertIn(helper.CREDENTIAL, output.getvalue())

    def test_non_tty_and_echo_fallback_refused(self):
        with patch.object(helper.sys.stdin, "isatty", return_value=False), patch.object(helper.getpass, "getpass", side_effect=AssertionError()):
            with self.assertRaises(helper.ProvisionError):
                helper.prompt_password()
        def fallback(*args, **kwargs):
            helper.warnings.warn("Cannot control echo", helper.getpass.GetPassWarning)
            raise AssertionError("must not read echoed input")
        with patch.object(helper.sys.stdin, "isatty", return_value=True), patch.object(helper.sys.stderr, "isatty", return_value=True), patch.object(helper.os, "open", return_value=123), patch.object(helper.os, "isatty", return_value=True), patch.object(helper.os, "close"), patch.object(helper.getpass, "getpass", side_effect=fallback):
            with self.assertRaises(helper.ProvisionError):
                helper.prompt_password()

    def test_two_hidden_inputs_must_agree(self):
        for values, succeeds in (([SECRET, SECRET], True), ([SECRET, "other-fixture"], False)):
            with patch.object(helper.sys.stdin, "isatty", return_value=True), patch.object(helper.sys.stderr, "isatty", return_value=True), patch.object(helper.os, "open", return_value=123), patch.object(helper.os, "isatty", return_value=True), patch.object(helper.os, "close"), patch.object(helper.getpass, "getpass", side_effect=values) as prompt:
                if succeeds:
                    self.assertEqual(helper.prompt_password(), SECRET)
                else:
                    with self.assertRaises(helper.ProvisionError) as caught:
                        helper.prompt_password()
                    self.assertNotIn(SECRET, str(caught.exception))
                self.assertEqual(prompt.call_count, 2)

    def test_argument_misuse_never_echoes_password(self):
        for arguments in (["--provision", SECRET], ["--password", SECRET], ["--provision=" + SECRET], [SECRET]):
            with patch.object(helper, "prompt_password", side_effect=AssertionError()), patch.object(helper, "send_secret", side_effect=AssertionError()):
                with contextlib.redirect_stdout(io.StringIO()) as stdout, contextlib.redirect_stderr(io.StringIO()) as stderr:
                    self.assertEqual(helper.main(arguments), 1)
            self.assertNotIn(SECRET, stdout.getvalue() + stderr.getvalue())

    def test_fixed_pinned_ssh_command_has_no_password(self):
        command = helper.ssh_command()
        self.assertEqual(command[-2], "vps-1")
        for flag in ("StrictHostKeyChecking=yes", "IdentityAgent=none", "ClearAllForwardings=yes", "ForwardAgent=no", "ControlPath=none"):
            self.assertIn(flag, command)
        self.assertNotIn(SECRET, repr(command))
        self.assertIn('NAME = "imap-password"', helper.REMOTE_PROGRAM)
        self.assertNotIn("systemctl", helper.REMOTE_PROGRAM)

    def test_transport_secret_is_only_stdin_and_failure_diagnostics_are_hidden(self):
        program = """import os,sys
data=sys.stdin.buffer.read()
assert data.endswith(b'\\n') and data.startswith(b'fixture-')
assert b'fixture-' not in repr(sys.argv).encode()
assert b'fixture-' not in repr(dict(os.environ)).encode()
sys.stdout.write('credential-created\\n')
"""
        helper.send_secret(SECRET, _command=[sys.executable, "-I", "-c", program])
        bad_program = "import sys; data=sys.stdin.buffer.read(); sys.stdout.buffer.write(data); sys.stderr.buffer.write(data); sys.exit(1)"
        with contextlib.redirect_stdout(io.StringIO()) as stdout, contextlib.redirect_stderr(io.StringIO()) as stderr:
            with self.assertRaises(helper.ProvisionError) as caught:
                helper.send_secret(SECRET, _command=[sys.executable, "-I", "-c", bad_program])
        self.assertNotIn(SECRET, str(caught.exception) + stdout.getvalue() + stderr.getvalue())

    def test_exclusive_private_publication_preserves_existing_credential(self):
        root, directory = self.fixture()
        self.publish(directory)
        target = directory / "imap-password"
        self.assertEqual(target.read_bytes(), (SECRET + "\n").encode())
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        self.assertEqual(target.stat().st_nlink, 1)
        before = target.stat().st_ino
        with self.assertRaises(ValueError):
            self.publish(directory)
        self.assertEqual(target.stat().st_ino, before)
        self.assertEqual(list(directory.iterdir()), [target])

    def test_symlink_and_fifo_targets_are_not_followed_or_replaced(self):
        for attack in ("directory-symlink", "target-symlink", "target-fifo"):
            with self.subTest(attack=attack):
                root, directory = self.fixture()
                target = directory / "imap-password"
                if attack == "directory-symlink":
                    alias = root / "alias"
                    alias.symlink_to(directory)
                    directory = alias
                elif attack == "target-symlink":
                    target.symlink_to(root / "missing")
                else:
                    os.mkfifo(target, 0o600)
                with self.assertRaises((ValueError, OSError)):
                    self.publish(directory)
                self.assertFalse((root / "missing").exists())
                self.assertFalse(any(p.name.startswith(".imap-password-") for p in directory.iterdir()))


if __name__ == "__main__":
    unittest.main()
