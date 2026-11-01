#!/usr/bin/env python3
"""Fetch read-only server status through a pinned SSH host; never falls back locally."""

import argparse
import datetime
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import stat
import subprocess
import sys
import time

SSH = "/usr/bin/ssh"
COMMAND = "/usr/local/libexec/mail-guardian-status"
INSTANCE = re.compile(r"[a-z0-9][a-z0-9-]{0,28}\Z")
USER = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
HOST = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
STATE = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
SAFE_PATH = re.compile(r"/[A-Za-z0-9_./-]+\Z")


def safe_file(name, private=False):
    path = Path(name)
    if not SAFE_PATH.fullmatch(name) or not path.is_absolute():
        raise ValueError("SSH paths must be absolute and contain only simple path characters")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & (0o077 if private else 0o022):
        raise ValueError("unsafe SSH key or known-hosts file")
    for parent in (path.parent, *path.parent.parents):
        parent_info = parent.lstat()
        if not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid not in (0, os.getuid()) or parent_info.st_mode & 0o022:
            raise ValueError("unsafe SSH file parent directory")
    return str(path)


def ssh_args(host, user, port, key, known_hosts):
    if not HOST.fullmatch(host) or ".." in host or not USER.fullmatch(user) or not (1 <= port <= 65535):
        raise ValueError("invalid server address")
    safe_file(key, private=True)
    safe_file(known_hosts)
    return [SSH, "-F", "/dev/null", "-T", "-p", str(port), "-i", key,
            "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
            "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + known_hosts,
            "-o", "GlobalKnownHostsFile=/dev/null", "-o", "VerifyHostKeyDNS=no",
            "-o", "UpdateHostKeys=no", "-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no",
            "-o", "ForwardX11=no", "-o", "ControlMaster=no", "-o", "ControlPath=none",
            "-o", "ConnectionAttempts=1", "-o", "ConnectTimeout=10", user + "@" + host, COMMAND]


def bounded_ssh(args, request, timeout=20, limit=16384):
    env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": str(Path.home())}
    p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         env=env, start_new_session=True)
    buffers = {p.stdout: bytearray(), p.stderr: bytearray()}
    end = time.monotonic() + timeout
    try:
        p.stdin.write(request)
        p.stdin.close()
        with selectors.DefaultSelector() as selector:
            for stream in buffers:
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map():
                remaining = end - time.monotonic()
                if remaining <= 0:
                    raise ValueError("remote request timed out")
                for key, _ in selector.select(min(remaining, 0.1)):
                    chunk = os.read(key.fileobj.fileno(), 4096)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    buffers[key.fileobj].extend(chunk)
                    if len(buffers[key.fileobj]) > limit:
                        raise ValueError("remote response exceeded limit")
            p.wait(timeout=max(0.001, end - time.monotonic()))
            if p.returncode:
                raise ValueError("remote connection or command failed")
            return bytes(buffers[p.stdout])
    finally:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        p.wait()
        p.stdout.close()
        p.stderr.close()


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate response field")
        result[key] = value
    return result


def validate_response(raw, instance, expected_id, nonce):
    obj = json.loads(raw, object_pairs_hook=unique_pairs)
    if not isinstance(obj, dict) or set(obj) != {"protocol", "instance", "server_id", "nonce", "timer", "service"}:
        raise ValueError("invalid response")
    if type(obj["protocol"]) is not int or obj["protocol"] != 1 or obj["instance"] != instance or obj["server_id"] != expected_id or obj["nonce"] != nonce:
        raise ValueError("remote protocol or identity mismatch")
    for name, fields in (("timer", {"LoadState", "ActiveState", "SubState", "UnitFileState"}),
                         ("service", {"LoadState", "ActiveState", "SubState", "Result"})):
        unit = obj[name]
        if not isinstance(unit, dict) or set(unit) != fields or any(not isinstance(v, str) or not STATE.fullmatch(v) for v in unit.values()):
            raise ValueError("invalid unit status")
    return obj


def status(host, user, port, key, known_hosts, instance, expected_id, runner=bounded_ssh):
    if not INSTANCE.fullmatch(instance) or not HEX64.fullmatch(expected_id):
        raise ValueError("invalid instance or expected identity")
    args = ssh_args(host, user, port, key, known_hosts)
    nonce = secrets.token_hex(16)
    request = json.dumps({"protocol": 1, "operation": "status", "instance": instance, "nonce": nonce}, separators=(",", ":")).encode()
    result = validate_response(runner(args, request), instance, expected_id, nonce)
    result["observed_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    result["scope"] = "systemd unit state only; mailbox health, configuration and last successful run are not assessed"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--user", required=True)
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--key", required=True)
    parser.add_argument("--known-hosts", required=True)
    parser.add_argument("--instance", required=True)
    parser.add_argument("--server-id", required=True, help="expected server identity, verified independently")
    args = parser.parse_args()
    try:
        print(json.dumps(status(args.host, args.user, args.port, args.key, args.known_hosts, args.instance, args.server_id), indent=2))
    except (OSError, ValueError, subprocess.SubprocessError):
        print("Remote status unavailable; no local worker was started.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
