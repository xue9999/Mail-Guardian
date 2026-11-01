#!/usr/bin/env python3
"""Synthetic secret transport and private-file fixtures; no SSH or real credentials."""

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

spec = importlib.util.spec_from_file_location("guardian_provision_healthchecks", Path(__file__).with_name("healthchecks.py"))
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
remote = {"__name__": "fixture"}
exec(compile(helper.REMOTE_PROGRAM, "remote-fixture", "exec"), remote)
SECRET = "https://hc-ping.com/12345678-1234-4234-8234-123456789abc"


class Fixture:
    def __init__(self):
        # A trusted private parent avoids relying on a world-writable /tmp path
        # in tests of the production root-owned-parent policy.
        self.temp = tempfile.TemporaryDirectory(prefix=".guardian-provision-test-", dir=Path.home())
        self.root = Path(self.temp.name).resolve()
        self.directory = self.root / "credentials"
        self.directory.mkdir(mode=0o700)
        self.owner = os.geteuid()

    def publish(self):
        return remote["publish_secret"]((SECRET + "\n").encode(), str(self.directory), self.owner)

    def close(self):
        self.temp.cleanup()


class HealthchecksProvisionTests(unittest.TestCase):
    def test_url_validation_matches_fixed_consumer_scope(self):
        self.assertEqual(helper.validate_url(SECRET), SECRET)
        for value in (SECRET + "/fail", SECRET + "?x=y", SECRET + "#x", SECRET + "/",
                      SECRET.upper(), SECRET + "\n", " " + SECRET,
                      SECRET.replace("hc-ping.com", "hc-ping.com.evil.invalid"),
                      SECRET.replace("hc-ping.com", "user@hc-ping.com"),
                      SECRET.replace("hc-ping.com", "hc-ping.com:443"),
                      SECRET.replace("https", "http"), SECRET + "\x00", "secret-invalid"):
            with self.subTest(value=value):
                with self.assertRaises(helper.ProvisionError) as caught:
                    helper.validate_url(value)
                self.assertNotIn(value, str(caught.exception))

    def test_default_action_does_not_prompt_or_connect(self):
        with patch.object(helper, "prompt_url", side_effect=AssertionError()), patch.object(helper, "send_secret", side_effect=AssertionError()):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(helper.main([]), 0)
        self.assertIn(helper.CREDENTIAL, output.getvalue())

    def test_non_tty_is_refused_before_getpass(self):
        with patch.object(helper.sys.stdin, "isatty", return_value=False), patch.object(helper.getpass, "getpass", side_effect=AssertionError()):
            with self.assertRaises(helper.ProvisionError):
                helper.prompt_url()

    def test_argument_misuse_never_echoes_a_supplied_credential(self):
        for arguments in (["--provision", SECRET], ["--url", SECRET],
                          ["--provision=" + SECRET], [SECRET]):
            with self.subTest(arguments=arguments):
                with patch.object(helper, "prompt_url", side_effect=AssertionError()), patch.object(helper, "send_secret", side_effect=AssertionError()):
                    with contextlib.redirect_stdout(io.StringIO()) as stdout, contextlib.redirect_stderr(io.StringIO()) as stderr:
                        self.assertEqual(helper.main(arguments), 1)
                self.assertNotIn(SECRET, stdout.getvalue() + stderr.getvalue())

    def test_getpass_echo_fallback_is_refused(self):
        def echo_warning(*args, **kwargs):
            helper.warnings.warn("Cannot control echo", helper.getpass.GetPassWarning)
            raise AssertionError("must not read echoed input")
        with patch.object(helper.sys.stdin, "isatty", return_value=True), patch.object(helper.sys.stderr, "isatty", return_value=True), patch.object(helper.os, "open", return_value=123), patch.object(helper.os, "isatty", return_value=True), patch.object(helper.os, "close"), patch.object(helper.getpass, "getpass", side_effect=echo_warning):
            with self.assertRaises(helper.ProvisionError):
                helper.prompt_url()

    def test_fixed_command_contains_no_credential_or_general_target_option(self):
        command = helper.ssh_command()
        self.assertEqual(command[-2], "vps-1")
        self.assertIn("StrictHostKeyChecking=yes", command)
        self.assertIn("IdentityAgent=none", command)
        self.assertIn("ClearAllForwardings=yes", command)
        self.assertNotIn(SECRET, repr(command))
        self.assertIn("sudo -n /usr/bin/python3 -I -c", command[-1])
        self.assertNotIn("systemctl", helper.REMOTE_PROGRAM)

    def test_transport_sends_secret_only_as_stdin(self):
        # A fake child checks its stdin, argv and environment without recording
        # any secret on disk or invoking SSH.
        program = """import os,sys
data=sys.stdin.buffer.read()
assert data.startswith(b'https://hc-ping.com/') and data.endswith(b'\\n')
assert b'https://hc-ping.com/' not in repr(sys.argv).encode()
assert b'https://hc-ping.com/' not in repr(dict(os.environ)).encode()
sys.stdout.write('credential-created\\n')
"""
        helper.send_secret(SECRET, _command=[sys.executable, "-I", "-c", program])

    def test_transport_never_repeats_remote_diagnostics(self):
        program = "import sys; data=sys.stdin.buffer.read(); sys.stdout.buffer.write(data); sys.stderr.buffer.write(data); sys.exit(1)"
        with contextlib.redirect_stdout(io.StringIO()) as stdout, contextlib.redirect_stderr(io.StringIO()) as stderr:
            with self.assertRaises(helper.ProvisionError) as caught:
                helper.send_secret(SECRET, _command=[sys.executable, "-I", "-c", program])
        self.assertNotIn(SECRET, str(caught.exception) + stdout.getvalue() + stderr.getvalue())

    def test_transport_bounds_output_and_elapsed_wait(self):
        for program, timeout in (("import sys; sys.stdin.buffer.read(); sys.stdout.write('x'*100000)", 2),
                                 ("import sys,time; sys.stdin.buffer.read(); time.sleep(10)", 0.05)):
            with self.assertRaises(helper.ProvisionError):
                helper.send_secret(SECRET, _command=[sys.executable, "-I", "-c", program], _timeout=timeout)

    def test_private_atomic_publication_and_existing_file_preservation(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        fixture.publish()
        target = fixture.directory / "healthchecks-url"
        self.assertEqual(target.read_bytes(), (SECRET + "\n").encode())
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        self.assertEqual(target.stat().st_nlink, 1)
        before = target.stat().st_ino
        with self.assertRaises(ValueError):
            fixture.publish()
        self.assertEqual(target.stat().st_ino, before)
        self.assertEqual(list(fixture.directory.iterdir()), [target])

    def test_publication_refuses_path_and_target_attacks(self):
        for attack in ("directory-mode", "writable-parent", "directory-symlink", "target-symlink", "target-fifo"):
            with self.subTest(attack=attack):
                fixture = Fixture()
                try:
                    target = fixture.directory / "healthchecks-url"
                    if attack == "directory-mode":
                        fixture.directory.chmod(0o755)
                    elif attack == "writable-parent":
                        fixture.root.chmod(0o777)
                    elif attack == "directory-symlink":
                        alias = fixture.root / "alias"
                        alias.symlink_to(fixture.directory)
                        fixture.directory = alias
                    elif attack == "target-symlink":
                        target.symlink_to(fixture.root / "missing")
                    else:
                        os.mkfifo(target, 0o600)
                    with self.assertRaises((ValueError, OSError)):
                        fixture.publish()
                    self.assertFalse(any(p.name.startswith(".healthchecks-url-") for p in fixture.directory.iterdir()))
                finally:
                    fixture.root.chmod(0o700)
                    fixture.close()

    def test_invalid_remote_input_creates_nothing(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        for raw in (b"", SECRET.encode(), (SECRET + "\n\n").encode(), b"x" * 257, b"\xff\n"):
            with self.assertRaises((ValueError, UnicodeError)):
                remote["publish_secret"](raw, str(fixture.directory), fixture.owner)
        self.assertEqual(list(fixture.directory.iterdir()), [])

    def test_sync_failure_never_deletes_published_credential(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        real_sync = remote["os"].fsync
        calls = []
        def failing_sync(fd):
            calls.append(fd)
            if len(calls) == 2:  # intent has linked NAME but directory sync fails
                raise OSError("fixture sync failure")
            return real_sync(fd)
        with patch.object(remote["os"], "fsync", side_effect=failing_sync):
            with self.assertRaises(OSError):
                fixture.publish()
        target = fixture.directory / "healthchecks-url"
        self.assertEqual(target.read_bytes(), (SECRET + "\n").encode())
        self.assertEqual(target.stat().st_nlink, 1)
        with self.assertRaises(ValueError):
            fixture.publish()


if __name__ == "__main__":
    unittest.main()
