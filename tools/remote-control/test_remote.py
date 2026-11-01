import io
import json
import os
import subprocess
import sys
import threading
import unittest
from unittest import mock

import client
import server


class RemoteProtocolTests(unittest.TestCase):
    instance = "pilot"
    machine = "ab" * 16
    nonce = "cd" * 16

    def request(self):
        return {"protocol": 1, "operation": "status", "instance": self.instance, "nonce": self.nonce}

    @staticmethod
    def runner(args):
        if args[2].endswith(".timer"):
            return b"LoadState=loaded\nActiveState=inactive\nSubState=dead\nUnitFileState=disabled\n"
        return b"LoadState=loaded\nActiveState=inactive\nSubState=dead\nResult=success\n"

    def test_roundtrip_binds_identity_nonce_and_unit_state(self):
        response = server.response(self.request(), self.instance, self.machine, self.runner)
        parsed = client.validate_response(json.dumps(response).encode(), self.instance, response["server_id"], self.nonce)
        self.assertEqual(parsed["timer"]["UnitFileState"], "disabled")
        for instance, identity, nonce in (("other", response["server_id"], self.nonce),
                                          (self.instance, "0" * 64, self.nonce),
                                          (self.instance, response["server_id"], "0" * 32)):
            with self.assertRaises(ValueError):
                client.validate_response(json.dumps(response).encode(), instance, identity, nonce)

    def test_request_is_strict(self):
        request = self.request()
        self.assertEqual(server.read_request(io.BytesIO(json.dumps(request).encode())), request)
        for raw in (b"{}", b"x" * 4097, b'{"protocol":1,"protocol":1}', json.dumps({**request, "operation": "run"}).encode(),
                    json.dumps({**request, "instance": "pilot;id"}).encode(), json.dumps({**request, "protocol": True}).encode(),
                    json.dumps(request).encode() + b"{}"):
            with self.subTest(raw=raw[:50]), self.assertRaises((ValueError, json.JSONDecodeError)):
                server.read_request(io.BytesIO(raw))

    def test_rejects_protocol_extra_and_duplicate_fields(self):
        response = server.response(self.request(), self.instance, self.machine, self.runner)
        for raw in (json.dumps({**response, "protocol": 2}).encode(),
                    json.dumps({**response, "extra": True}).encode(),
                    json.dumps(response).encode() + b"{}", b'{"protocol":1,"protocol":1}'):
            with self.assertRaises((ValueError, json.JSONDecodeError)):
                client.validate_response(raw, self.instance, response["server_id"], self.nonce)

    def test_server_rejects_wrong_instance_or_invalid_unit_output(self):
        with self.assertRaises(ValueError):
            server.response(self.request(), "another", self.machine, self.runner)
        with self.assertRaises(ValueError):
            server.response(self.request(), self.instance, self.machine, lambda _: b"LoadState=loaded\n")

    def test_client_uses_fixed_command_and_fails_closed(self):
        with mock.patch.object(client, "safe_file", side_effect=lambda name, private=False: name):
            args = client.ssh_args("server.example", "mgstatus", 22, "/tmp/key", "/tmp/known")
            self.assertEqual(args[-1], client.COMMAND)
            self.assertIn("StrictHostKeyChecking=yes", args)
            self.assertIn("/dev/null", args)
            with self.assertRaises(ValueError):
                client.ssh_args("server; touch /tmp/bad", "mgstatus", 22, "/tmp/key", "/tmp/known")
            with self.assertRaises(ValueError):
                client.status("server.example", "mgstatus", 22, "/tmp/key", "/tmp/known", "pilot", "0" * 64,
                              runner=mock.Mock(side_effect=ValueError("disconnected")))

    def test_bounded_process_output_and_deadline(self):
        with self.assertRaises(ValueError):
            client.bounded_ssh([sys.executable, "-c", "import sys; sys.stdout.write('x'*100000)"], b"", timeout=3, limit=1024)
        with self.assertRaises(ValueError):
            client.bounded_ssh([sys.executable, "-c", "import sys; sys.stderr.write('x'*100000)"], b"", timeout=3, limit=1024)
        with self.assertRaises((ValueError, subprocess.TimeoutExpired)):
            client.bounded_ssh([sys.executable, "-c", "import time; time.sleep(2)"], b"", timeout=0.1)
        with self.assertRaises(ValueError):
            server.bounded_run([sys.executable, "-c", "print('x'*100000)"], timeout=3, limit=1024)

    def test_server_rejects_idle_or_oversize_request(self):
        read_fd, write_fd = os.pipe()
        try:
            with self.assertRaises(ValueError):
                server.bounded_request(read_fd, timeout=0.1)
        finally:
            os.close(read_fd)
            os.close(write_fd)
        read_fd, write_fd = os.pipe()
        errors = []

        def produce_oversize():
            try:
                # A macOS pipe may hold only 4096 bytes. Writing on the test
                # thread before starting the reader can deadlock the fixture.
                payload = b"x" * 4097
                while payload:
                    count = os.write(write_fd, payload)
                    payload = payload[count:]
            except OSError as error:
                errors.append(error)
            finally:
                os.close(write_fd)

        writer = threading.Thread(target=produce_oversize, daemon=True)
        writer.start()
        try:
            with self.assertRaisesRegex(ValueError, "request too large"):
                server.bounded_request(read_fd, timeout=3)
        finally:
            os.close(read_fd)
            writer.join(timeout=3)
        self.assertFalse(writer.is_alive(), "fixture writer did not terminate")
        self.assertEqual(errors, [])



if __name__ == "__main__":
    unittest.main()
