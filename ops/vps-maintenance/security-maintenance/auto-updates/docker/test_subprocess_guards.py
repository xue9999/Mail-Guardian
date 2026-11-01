"""Exercise the updater's bounded real subprocess handling, without host changes."""

import subprocess
import sys
import time
import unittest
from unittest import mock

import engine


class SubprocessGuardTests(unittest.TestCase):
    def test_captures_stdout_and_stderr(self):
        result = engine.run([sys.executable, "-c", "import sys;print('ok');print('note',file=sys.stderr)"])
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "ok\n")
        self.assertEqual(result.stderr, "note\n")

    def test_stdin_is_closed(self):
        result = engine.run([sys.executable, "-c", "import sys;print(len(sys.stdin.read()))"], timeout=2)
        self.assertEqual(result.stdout.strip(), "0")

    def test_command_output_limit_fails_without_returning_content(self):
        with mock.patch.object(engine, "OUTPUT_LIMIT", 1024):
            with self.assertRaisesRegex(engine.UpdateError, "exceeded output limit"):
                engine.run([sys.executable, "-c", "print('x'*100000)"], timeout=2)

    def test_timeout_terminates_entire_group_even_if_parent_exits(self):
        # The child inherits stdout/stderr and outlives its parent. A parent-only
        # kill would leave the inherited pipe open, so this must return promptly.
        code = ("import subprocess,sys; "
                "subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']); "
                "sys.exit(0)")
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            engine.run([sys.executable, "-c", code], timeout=0.25)
        self.assertLess(time.monotonic() - started, 4)

    def test_nonzero_exit_can_be_inspected_or_rejected(self):
        command = [sys.executable, "-c", "import sys;sys.exit(7)"]
        self.assertEqual(engine.run(command, check=False).returncode, 7)
        with self.assertRaisesRegex(engine.UpdateError, "exit 7"):
            engine.run(command)


if __name__ == "__main__":
    unittest.main()
