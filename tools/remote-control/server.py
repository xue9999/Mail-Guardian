#!/usr/bin/python3 -I
"""Read-only Guardian status protocol endpoint. No mail or credentials accessed."""

import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

PROTOCOL = 1
INSTANCE = re.compile(r"[a-z0-9][a-z0-9-]{0,28}\Z")
NONCE = re.compile(r"[0-9a-f]{32}\Z")
MACHINE = re.compile(r"[0-9a-f]{32}\Z")
STATE = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate request field")
        result[key] = value
    return result


def read_request(stream):
    raw = stream.read(4097)
    if len(raw) > 4096:
        raise ValueError("request too large")
    obj = json.loads(raw, object_pairs_hook=unique_pairs)
    if not isinstance(obj, dict) or set(obj) != {"protocol", "operation", "instance", "nonce"}:
        raise ValueError("invalid request")
    if type(obj["protocol"]) is not int or obj["protocol"] != PROTOCOL or obj["operation"] != "status":
        raise ValueError("unsupported request")
    if not isinstance(obj["instance"], str) or not INSTANCE.fullmatch(obj["instance"]):
        raise ValueError("invalid instance")
    if not isinstance(obj["nonce"], str) or not NONCE.fullmatch(obj["nonce"]):
        raise ValueError("invalid nonce")
    return obj


def bounded_request(fd, timeout=10):
    data = bytearray()
    deadline = time.monotonic() + timeout
    with selectors.DefaultSelector() as selector:
        selector.register(fd, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("request timeout")
            if not selector.select(remaining):
                raise ValueError("request timeout")
            chunk = os.read(fd, 4097 - len(data))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > 4096:
                raise ValueError("request too large")
    import io
    return read_request(io.BytesIO(data))


def bounded_run(args, timeout=5, limit=8192):
    process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}, start_new_session=True)
    streams = {process.stdout: bytearray(), process.stderr: bytearray()}
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            for stream in streams:
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError("dependency timeout")
                for key, _ in selector.select(min(remaining, 0.1)):
                    chunk = os.read(key.fileobj.fileno(), 4096)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    streams[key.fileobj].extend(chunk)
                    if len(streams[key.fileobj]) > limit:
                        raise ValueError("dependency output limit")
            process.wait(timeout=max(0.001, deadline - time.monotonic()))
            if process.returncode:
                raise ValueError("dependency failed")
            return bytes(streams[process.stdout])
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        process.stdout.close()
        process.stderr.close()


def unit_status(instance, unit_kind, runner=bounded_run):
    keys = ("LoadState", "ActiveState", "SubState", "UnitFileState") if unit_kind == "timer" else ("LoadState", "ActiveState", "SubState", "Result")
    raw = runner(["/usr/bin/systemctl", "show", "mail-guardian@" + instance + "." + unit_kind,
                  *["--property=" + key for key in keys]])
    values = {}
    for line in raw.decode("utf-8", "strict").splitlines():
        key, separator, value = line.partition("=")
        if not separator or key not in keys or key in values or not STATE.fullmatch(value):
            raise ValueError("invalid unit metadata")
        values[key] = value
    if set(values) != set(keys):
        raise ValueError("incomplete unit metadata")
    return values


def response(request, instance, machine, runner=bounded_run):
    instance, machine = instance.strip(), machine.strip()
    if not INSTANCE.fullmatch(instance) or not MACHINE.fullmatch(machine) or request["instance"] != instance:
        raise ValueError("instance or machine identity mismatch")
    server_id = hashlib.sha256(("mail-guardian-status-v1\0" + machine + "\0" + instance).encode()).hexdigest()
    return {"protocol": PROTOCOL, "instance": instance, "server_id": server_id, "nonce": request["nonce"],
            "timer": unit_status(instance, "timer", runner), "service": unit_status(instance, "service", runner)}


def read_admin_file(name):
    path = Path(name)
    for part in (path.parent, *path.parent.parents):
        info = part.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("untrusted administrator path")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("untrusted administrator file")
        with os.fdopen(fd, "rb", closefd=False) as source:
            raw = source.read(1025)
        if len(raw) > 1024:
            raise ValueError("administrator file too large")
        return raw.decode("ascii", "strict")
    finally:
        os.close(fd)


def main():
    try:
        request = bounded_request(sys.stdin.fileno())
        # These are administrator-owned installation/OS files, never worker state.
        instance = read_admin_file("/etc/mail-guardian/instance")
        machine = read_admin_file("/etc/machine-id")
        result = response(request, instance, machine)
        print(json.dumps(result, separators=(",", ":")))
    except Exception:
        # Do not relay dependency output or host details to the client.
        print("status unavailable", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
