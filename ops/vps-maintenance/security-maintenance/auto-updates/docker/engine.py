#!/usr/bin/python3
"""Shared Docker transaction primitives used by simple-updates/docker/updater.py.

The CLI in this module is an earlier experimental coordinator and is not the
scheduled production entrypoint. Keep its imported helpers and tests together;
see ops/vps-maintenance/README.md for the current owner and dependency map.
"""
import argparse
from functools import cmp_to_key
import fcntl
import grp
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import re
import selectors
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

from docker_auto_update import patch_update_allowed, simulation_is_safe
import transaction_journal

PACKAGES = ("docker-ce", "docker-ce-cli", "containerd.io", "docker-buildx-plugin", "docker-compose-plugin")
TIMERS = ("mail-guardian@pilot.timer", "mail-guardian-backup@pilot.timer")
WORKERS = ("mail-guardian@pilot.service", "mail-guardian-backup@pilot.service")
INSTANCE = Path("/etc/mail-guardian/pilot")
MARKER = INSTANCE / "migration-pending"
LOCK = INSTANCE / "migration.lock"
STATE = Path("/var/lib/vps-docker-auto-update")
DOCKER_SOURCE = Path("/etc/apt/sources.list.d/docker.sources")
DPKG_FRONTEND_LOCK = Path("/var/lib/dpkg/lock-frontend")
EXPECTED = {f"mail-guardian-pilot-{s}-1": s for s in ("rspamd", "redis", "unbound")}
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "HOME": "/root", "DEBIAN_FRONTEND": "noninteractive",
       # APT hooks must not restart the updater in the middle of its durable
       # transaction. The Ubuntu coordinator activates stale services afterward.
       "NEEDRESTART_SUSPEND": "1"}
OUTPUT_LIMIT = 4 * 1024 * 1024


class UpdateError(Exception):
    pass


def ubuntu_codename(path=Path("/etc/os-release")):
    """Known supported host lines; never infer a distribution release upgrade."""
    fields = {}
    for line in path.read_text().splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key, value = line.split("=", 1)
        if key in fields:
            raise UpdateError("ambiguous Ubuntu release metadata")
        fields[key] = value.strip('"')
    release = fields.get("VERSION_CODENAME", "")
    supported = {"24.04": "noble", "26.04": "resolute", "26.10": "stonking"}
    if fields.get("ID") != "ubuntu" or supported.get(fields.get("VERSION_ID")) != release:
        raise UpdateError("Ubuntu host release needs qualification before package maintenance")
    return release


def run(args, *, timeout=120, cwd=None, check=True, frontend_locked=False):
    env = dict(ENV)
    if frontend_locked:
        env["DPKG_FRONTEND_LOCKED"] = "1"
    p = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, env=env, cwd=cwd, start_new_session=True)
    deadline = time.monotonic() + timeout
    chunks = {"stdout": bytearray(), "stderr": bytearray()}
    completed = False
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(p.stdout, selectors.EVENT_READ, "stdout")
            selector.register(p.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                left = deadline - time.monotonic()
                if left <= 0:
                    raise subprocess.TimeoutExpired(args, timeout)
                events = selector.select(left)
                if not events:
                    raise subprocess.TimeoutExpired(args, timeout)
                for key, _ in events:
                    block = os.read(key.fileobj.fileno(), 65536)
                    if not block:
                        selector.unregister(key.fileobj)
                        continue
                    chunks[key.data].extend(block)
                    if sum(len(value) for value in chunks.values()) > OUTPUT_LIMIT:
                        raise UpdateError(f"{args[0]} exceeded output limit")
        try:
            p.wait(timeout=max(0.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            raise subprocess.TimeoutExpired(args, timeout) from None
        completed = True
    finally:
        if not completed:
            # Stop the private process group, including APT or Compose children.
            # A timeout after mutation still leaves Guardian fenced.
            try: os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError: pass
        if p.poll() is None:
            try: p.wait(timeout=1)
            except subprocess.TimeoutExpired: pass
        if p.stdout: p.stdout.close()
        if p.stderr: p.stderr.close()
    if check and p.returncode:
        # Never print stdout/stderr from commands that might contain application secrets.
        raise UpdateError(f"{args[0]} failed with exit {p.returncode}")
    return subprocess.CompletedProcess(args, p.returncode,
                                       chunks["stdout"].decode("utf-8", "replace"),
                                       chunks["stderr"].decode("utf-8", "replace"))


def remaining(deadline, upper=120):
    if deadline is None:
        return upper
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise UpdateError("health check deadline expired")
    return min(upper, seconds)


def unit_state(unit, deadline=None):
    result = run(["systemctl", "show", unit, "-p", "LoadState", "-p", "ActiveState"],
                 timeout=remaining(deadline, 10))
    fields = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    if fields.get("LoadState") != "loaded" or fields.get("ActiveState") not in (
            "active", "inactive", "failed", "activating", "deactivating", "reloading"):
        raise UpdateError(f"cannot establish state of {unit}")
    return fields["ActiveState"]


def unit_active(unit, deadline=None):
    return unit_state(unit, deadline) == "active"


def unit_busy(unit):
    # A failed unit may indicate unresolved mailbox or backup work.
    return unit_state(unit) != "inactive"


def candidates():
    import apt
    import apt_pkg
    cache = apt.Cache()
    held = set(run(["apt-mark", "showhold"]).stdout.splitlines())
    targets, baseline, skipped = {}, {}, {}
    for name in PACKAGES:
        if name not in cache or not cache[name].is_installed:
            continue
        pkg = cache[name]
        old = pkg.installed.version
        candidate = pkg.candidate
        if candidate is None:
            raise UpdateError(f"no candidate for {name}")
        new = candidate.version
        baseline[name] = old
        if name in held:
            skipped[name] = {"installed": old, "candidate": new, "reason": "package is held"}
            continue
        if new == old:
            continue
        def trusted(version):
            return any(o.origin == "Docker" and o.archive == "resolute" and o.component == "stable" and
                       o.site == "download.docker.com" for o in version.origins)
        if not trusted(candidate):
            raise UpdateError(f"candidate source is not Docker stable for {name}")
        if not patch_update_allowed(old, new):
            skipped[name] = {"installed": old, "candidate": new,
                             "reason": "new release line requires compatibility qualification; "
                                       "automatic stable-series promotion is not implemented"}
        same_line = [v.version for v in pkg.versions if v.policy_priority > 0 and trusted(v) and patch_update_allowed(old, v.version)]
        if same_line:
            targets[name] = max(same_line, key=cmp_to_key(apt_pkg.version_compare))
    if not baseline:
        raise UpdateError("no installed Docker packages")
    return baseline, targets, skipped


def simulation(targets, baseline):
    if not targets:
        return
    p = run(["apt-get", "-s", "--no-install-recommends", "--no-remove", "--only-upgrade", "install"] +
            [f"{k}={v}" for k, v in targets.items()])
    if not simulation_is_safe(p.stdout, targets):
        raise UpdateError("APT simulated an unexpected transaction")
    for line in p.stdout.splitlines():
        m = re.match(r"^\s*Inst\s+(\S+)\s+\[([^\]]+)\]", line)
        if m and baseline.get(m.group(1)) != m.group(2):
            raise UpdateError("installed version changed during simulation")


def container_snapshot(deadline=None):
    p = run(["docker", "ps", "-a", "--format", "{{.Names}}"], timeout=remaining(deadline, 15))
    names = set(p.stdout.splitlines())
    if names != set(EXPECTED):
        raise UpdateError("unknown, missing or additional Docker workloads")
    result = {}
    for name, service in EXPECTED.items():
        # Inspect only necessary fields; environment and secret values are not read.
        fmt = '{{index .Config.Labels "com.docker.compose.project"}}|{{index .Config.Labels "com.docker.compose.service"}}|{{.State.Running}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|{{.Image}}|{{json .Mounts}}|{{json .HostConfig.PortBindings}}'
        row = run(["docker", "inspect", "--format", fmt, name], timeout=remaining(deadline, 15)).stdout.strip().split("|", 6)
        if len(row) != 7 or row[:4] != ["mail-guardian-pilot", service, "true", "healthy"]:
            raise UpdateError(f"{service} container is not ready")
        result[service] = row[4:]
    return result


def controller_stat(deadline):
    credential = INSTANCE / "credentials" / "rspamd-password"
    fd = os.open(credential, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise UpdateError("unsafe controller credential")
        raw = os.read(fd, 4097)
        if not raw or len(raw) > 4096:
            raise UpdateError("invalid controller credential")
        secret = raw.decode("utf-8").removesuffix("\n").removesuffix("\r")
        if not secret or "\r" in secret or "\n" in secret:
            raise UpdateError("invalid controller credential")
    finally:
        os.close(fd)
    conn = http.client.HTTPConnection("127.0.0.1", 11334, timeout=remaining(deadline, 8))
    try:
        conn.request("GET", "/stat", headers={"Password": secret})
        response = conn.getresponse()
        if response.status != 200:
            raise UpdateError("controller authentication or status check failed")
        body = bytearray()
        while True:
            if response.isclosed():
                break
            sock = conn.sock
            if sock is None:
                sock = getattr(getattr(getattr(response, "fp", None), "raw", None), "_sock", None)
            if sock is None:
                raise UpdateError("controller response socket unavailable")
            sock.settimeout(remaining(deadline, 8))
            chunk = response.read1(8192)
            if not chunk:
                break
            body.extend(chunk)
            if len(body) > 2 * 1024 * 1024:
                raise UpdateError("controller status response too large")
        if not isinstance(json.loads(body), dict):
            raise UpdateError("controller status response invalid")
    except http.client.HTTPException:
        raise UpdateError("controller status request failed") from None
    finally:
        conn.close()


def health(expected, timeout=180):
    deadline = time.monotonic() + timeout
    while True:
        try:
            if not all(unit_active(u, deadline) for u in ("docker.service", "containerd.service")):
                raise UpdateError("Docker or containerd is not active")
            run(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=remaining(deadline, 15))
            if container_snapshot(deadline) != expected:
                raise UpdateError("container image, mounts or ports changed")
            info = run(["docker", "exec", "mail-guardian-pilot-redis-1", "redis-cli", "--raw", "INFO", "persistence"], timeout=remaining(deadline, 15)).stdout
            fields = dict(line.split(":", 1) for line in info.splitlines() if ":" in line and not line.startswith("#"))
            for k, v in {"loading": "0", "aof_enabled": "1", "aof_last_write_status": "ok", "rdb_last_bgsave_status": "ok"}.items():
                if fields.get(k, "").strip() != v:
                    raise UpdateError("Redis persistence check failed")
            fsync = run(["docker", "exec", "mail-guardian-pilot-redis-1", "redis-cli", "--raw", "CONFIG", "GET", "appendfsync"], timeout=remaining(deadline, 15)).stdout.splitlines()
            if fsync != ["appendfsync", "always"]:
                raise UpdateError("Redis AOF fsync is not always")
            for port in (11333, 11334):
                p = run(["curl", "--noproxy", "*", "-fsS", "--max-time", "8", f"http://127.0.0.1:{port}/ping"], timeout=remaining(deadline, 10))
                if p.stdout.strip().lower() != "pong":
                    raise UpdateError("Rspamd ping failed")
            controller_stat(deadline)
            return
        except (UpdateError, OSError, ValueError, subprocess.TimeoutExpired):
            if time.monotonic() >= deadline:
                raise UpdateError("post-update health failed; recovery required")
            time.sleep(remaining(deadline, 5))


def acquire_fence():
    info = os.lstat(LOCK)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != grp.getgrnam("mg-pilot").gr_gid or stat.S_IMODE(info.st_mode) != 0o640 or info.st_nlink != 1:
        raise UpdateError("unsafe migration lock metadata")
    fd = os.open(LOCK, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    opened = os.fstat(fd)
    if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
        os.close(fd)
        raise UpdateError("migration lock changed")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise UpdateError("Guardian worker or backup is active")
    try:
        current = os.lstat(LOCK)
        held = os.fstat(fd)
        if (not stat.S_ISREG(current.st_mode) or current.st_uid != 0 or
                current.st_gid != grp.getgrnam("mg-pilot").gr_gid or
                stat.S_IMODE(current.st_mode) != 0o640 or current.st_nlink != 1 or
                (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino)):
            raise UpdateError("migration lock changed after acquisition")
    except BaseException:
        os.close(fd)
        raise
    return fd


def acquire_frontend_lock():
    """Serialize with APT/dpkg frontends; never create or remove lock files."""
    fd = os.open(DPKG_FRONTEND_LOCK, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        current = os.lstat(DPKG_FRONTEND_LOCK)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or
                stat.S_IMODE(info.st_mode) & 0o022 or
                (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino)):
            raise UpdateError("unsafe dpkg frontend lock")
        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        current = os.lstat(DPKG_FRONTEND_LOCK)
        held = os.fstat(fd)
        if (not stat.S_ISREG(current.st_mode) or current.st_uid != 0 or current.st_nlink != 1 or
                stat.S_IMODE(current.st_mode) & 0o022 or
                (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino)):
            raise UpdateError("dpkg frontend lock changed after acquisition")
        return fd
    except BaseException:
        os.close(fd)
        raise


def assert_frontend_lock_held(fd):
    """Check the whole-file POSIX lock and its owner from a separate process."""
    held = os.fstat(fd)
    current = os.lstat(DPKG_FRONTEND_LOCK)
    if (not stat.S_ISREG(held.st_mode) or held.st_uid != 0 or held.st_nlink != 1 or
            stat.S_IMODE(held.st_mode) & 0o022 or
            (held.st_dev, held.st_ino) != (current.st_dev, current.st_ino)):
        raise UpdateError("dpkg frontend lock identity changed")
    # F_GETLK ignores locks held by the querying process, so use a child.
    # Merely observing a conflicting lock is insufficient: another frontend
    # might have acquired it after this process accidentally released ours.
    # These native layouts are restricted to the supported 64-bit platforms;
    # an unknown platform must fail closed rather than guess an ABI.
    code = '''import ctypes, fcntl, os, platform, sys
if ctypes.sizeof(ctypes.c_void_p) != 8:
    sys.exit(2)
if sys.platform == "linux" and platform.machine() in ("x86_64", "aarch64"):
    fields = [("l_type", ctypes.c_short), ("l_whence", ctypes.c_short),
              ("l_start", ctypes.c_longlong), ("l_len", ctypes.c_longlong),
              ("l_pid", ctypes.c_int)]
elif sys.platform == "darwin" and platform.machine() in ("x86_64", "arm64"):
    fields = [("l_start", ctypes.c_longlong), ("l_len", ctypes.c_longlong),
              ("l_pid", ctypes.c_int), ("l_type", ctypes.c_short),
              ("l_whence", ctypes.c_short)]
else:
    sys.exit(2)
class Flock(ctypes.Structure):
    _fields_ = fields
f = os.open(sys.argv[1], os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
query = Flock()
query.l_type = fcntl.F_WRLCK
query.l_whence = os.SEEK_SET
found = Flock.from_buffer_copy(fcntl.fcntl(f, fcntl.F_GETLK, bytes(query)))
if (found.l_type == fcntl.F_WRLCK and found.l_pid == int(sys.argv[2])
        and found.l_whence == os.SEEK_SET and found.l_start == 0 and found.l_len == 0):
    sys.exit(10)
sys.exit(1)
'''
    result = run(["/usr/bin/python3", "-c", code, str(DPKG_FRONTEND_LOCK), str(os.getpid())],
                 timeout=5, check=False)
    if result.returncode != 10:
        raise UpdateError("dpkg frontend lock is not demonstrably held")


def create_marker(transaction):
    payload = json.dumps({"owner": "vps-docker-auto-update", "transaction": transaction,
                          "worker_authorized": False}).encode()
    # Prepare and sync a private inode before exclusively publishing the
    # stable marker name. A failed fstat/write/file-sync cannot leave an empty
    # migration-pending fence that blocks Guardian before mutation begins.
    fd, temporary = tempfile.mkstemp(prefix=".vps-docker-marker-", dir=INSTANCE)
    identity = None
    published = False
    try:
        identity = os.fstat(fd)
        with os.fdopen(fd, "wb") as f:
            fd = -1
            f.write(payload); f.flush(); os.fsync(f.fileno())
        # A hard link is exclusive: an existing marker is never overwritten.
        os.link(temporary, MARKER, follow_symlinks=False)
        published = True
        os.unlink(temporary)
        temporary = None
        d = os.open(INSTANCE, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(d)
        finally: os.close(d)
    except BaseException:
        # No package mutation has started at this point. Remove only the exact
        # inode we just created; never remove a pre-existing or replaced fence.
        try:
            current = os.lstat(MARKER) if published else None
            if (current is not None and identity is not None and
                    (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino)):
                os.unlink(MARKER)
                d = os.open(INSTANCE, os.O_RDONLY | os.O_DIRECTORY)
                try: os.fsync(d)
                finally: os.close(d)
        except OSError:
            # Failure to sync or remove may leave a conservative stale fence;
            # an independent watchdog is required before any deployment.
            pass
        raise
    finally:
        if fd >= 0:
            os.close(fd)
        if temporary is not None:
            try: os.unlink(temporary)
            except FileNotFoundError: pass
    return payload


def marker_identity(payload, *, _test_expected_uid=None):
    fd = os.open(MARKER, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        current = os.lstat(MARKER)
        identity = (opened.st_dev, opened.st_ino)
        owner = 0 if _test_expected_uid is None else _test_expected_uid
        if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != owner or opened.st_nlink != 1 or
                stat.S_IMODE(opened.st_mode) != 0o600 or
                identity != (current.st_dev, current.st_ino) or
                os.read(fd, 4097) != payload):
            raise UpdateError("update marker changed; refusing to remove")
        return identity
    finally:
        os.close(fd)


def clear_own_marker(payload, expected_identity=None, *, _test_expected_uid=None):
    identity = marker_identity(payload, _test_expected_uid=_test_expected_uid)
    if expected_identity is not None and identity != expected_identity:
        raise UpdateError("update marker identity changed; refusing to remove")
    MARKER.unlink()
    try:
        d = os.open(INSTANCE, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(d)
        finally: os.close(d)
    except OSError:
        # The removed marker is not known durable. Recreate it when possible
        # and require human recovery rather than declaring a clean update.
        try:
            fd = os.open(MARKER, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(payload); f.flush(); os.fsync(f.fileno())
            d = os.open(INSTANCE, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(d)
            finally: os.close(d)
        except OSError:
            pass
        raise UpdateError("update fence removal could not be synchronized; recovery required") from None


def save_packages(directory, versions, targets):
    # APT verifies downloads against signed metadata. Refuse to proceed unless
    # every exact requested version is available before taking the fence.
    source_info = os.lstat(DOCKER_SOURCE)
    if (not stat.S_ISREG(source_info.st_mode) or source_info.st_uid != 0 or
            source_info.st_mode & 0o022 or source_info.st_nlink != 1):
        raise UpdateError("unsafe Docker source configuration")
    source = DOCKER_SOURCE.read_text()
    fields = {}
    for line in source.splitlines():
        if line.lstrip().startswith("#"):
            continue
        if not line or line[0].isspace() or ":" not in line:
            raise UpdateError("Docker source configuration changed")
        key, value = line.split(":", 1)
        if key in fields:
            raise UpdateError("duplicate Docker source field")
        fields[key] = value.strip()
    required = {"Types": "deb", "URIs": "https://download.docker.com/linux/ubuntu", "Suites": ubuntu_codename(),
                "Components": "stable", "Architectures": "amd64", "Signed-By": "/etc/apt/keyrings/docker.asc"}
    if fields != required:
        raise UpdateError("Docker source configuration changed")
    for name in targets:
        run(["apt-get", "-o", f"Dir::Etc::sourcelist={DOCKER_SOURCE}",
             "-o", "Dir::Etc::sourceparts=-", "download", f"{name}={versions[name]}"],
            cwd=str(directory), timeout=240)
    debs = list(directory.glob("*.deb"))
    found = {}
    for deb in debs:
        name = run(["dpkg-deb", "-f", str(deb), "Package"]).stdout.strip()
        version = run(["dpkg-deb", "-f", str(deb), "Version"]).stdout.strip()
        if name not in targets or version != versions[name] or name in found:
            raise UpdateError("downloaded package identity mismatch")
        found[name] = (str(deb), hashlib.sha256(deb.read_bytes()).hexdigest())
        with deb.open("rb") as stream:
            os.fsync(stream.fileno())
    if set(found) != set(targets):
        raise UpdateError("downloaded packages incomplete")
    return found


def installed_inventory():
    p = run(["dpkg-query", "-W", "-f=${binary:Package}\\t${db:Status-Abbrev}\\t${Version}\\n"])
    result = {}
    for line in p.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) != 3:
            raise UpdateError("cannot parse installed package inventory")
        if fields[1].startswith("ii"):
            result[fields[0]] = fields[2]
    if not result:
        raise UpdateError("empty installed package inventory")
    return result


def inventory_matches(before, after, targets):
    expected = dict(before)
    expected.update(targets)
    return after == expected


def sync_directory(path):
    """Durably publish a transaction directory or its entries before fencing."""
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def initialize_journal(directory, baseline, targets, old_packages, new_packages, inventory, containers):
    """Persist the complete no-secret pre-mutation plan before publishing a fence."""
    images = transaction_journal.container_evidence(containers)
    plan = {"packages": [{"name": name, "installed": baseline[name], "target": targets[name],
                          "old_sha256": old_packages[name][1], "new_sha256": new_packages[name][1]}
                         for name in sorted(targets)],
            "inventory": inventory, "containers": images}
    return transaction_journal.initialize(directory.parent, directory.name, plan)


def advance_journal(record, next_phase):
    return transaction_journal.advance(STATE, record["transaction_id"], record["plan_sha256"],
                                       record["phase"], record["generation"], next_phase)


def acquire_updater_lock():
    """Serialize the entire update, including scan and preflight downloads."""
    path = STATE / ".updater.lock"
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(fd)
        current = os.lstat(path)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or
                stat.S_IMODE(info.st_mode) != 0o600 or
                (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino)):
            raise UpdateError("unsafe global updater lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        current = os.lstat(path)
        held = os.fstat(fd)
        if (not stat.S_ISREG(current.st_mode) or current.st_uid != 0 or current.st_nlink != 1 or
                stat.S_IMODE(current.st_mode) != 0o600 or
                (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino)):
            raise UpdateError("global updater lock changed after acquisition")
        os.fsync(fd)
        sync_directory(STATE)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _verify_updater_lock(updater_lock, owner):
    lock = os.fstat(updater_lock)
    path_lock = os.lstat(STATE / ".updater.lock")
    if (not stat.S_ISREG(lock.st_mode) or lock.st_uid != owner or lock.st_nlink != 1 or
            stat.S_IMODE(lock.st_mode) != 0o600 or
            (lock.st_dev, lock.st_ino) != (path_lock.st_dev, path_lock.st_ino)):
        raise UpdateError("unsafe updater lock during preflight cleanup")
    # Refuse an obviously unheld lock; the caller must have held this exact
    # open-file-description throughout the scan and preflight lifecycle.
    probe = os.open(STATE / ".updater.lock", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        try:
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            pass
        else:
            fcntl.flock(probe, fcntl.LOCK_UN)
            raise UpdateError("global updater lock was not held")
    finally:
        os.close(probe)
    fcntl.flock(updater_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)


def cleanup_preflight(preflight, updater_lock, *, _test_expected_uid=None):
    """Remove only abandoned, private pre-mutation staging under the updater lock."""
    owner = 0 if _test_expected_uid is None else _test_expected_uid
    if Path(preflight) != STATE / ".preflight":
        raise UpdateError("preflight cleanup path is outside update state")
    state_info = os.lstat(STATE)
    if (not stat.S_ISDIR(state_info.st_mode) or state_info.st_uid != owner or
            stat.S_IMODE(state_info.st_mode) != 0o700):
        raise UpdateError("unsafe update state directory")
    _verify_updater_lock(updater_lock, owner)
    info = os.lstat(preflight)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or stat.S_IMODE(info.st_mode) != 0o700:
        raise UpdateError("unsafe update preflight directory")
    if not getattr(shutil.rmtree, "avoids_symlink_attacks", False):
        raise UpdateError("safe preflight cleanup is unavailable")
    entries = list(preflight.iterdir())
    if len(entries) > 100:
        raise UpdateError("too many preflight directories; manual review required")

    for entry in entries:
        _validate_artifact_tree(entry, owner)
        # Python's fd-based implementation refuses symlink traversal. The
        # root-owned directory and verified global lock constrain concurrent
        # writers; unexpected metadata is rejected rather than deleted.
        shutil.rmtree(entry)
        sync_directory(preflight)


def _validate_artifact_tree(entry, owner):
    """Reject unknown, linked or externally writable transaction contents."""
    st = entry.lstat()
    if (not stat.S_ISDIR(st.st_mode) or st.st_uid != owner or
            stat.S_IMODE(st.st_mode) != 0o700 or
            not transaction_journal.IDENTIFIER.fullmatch(entry.name)):
        raise UpdateError("unexpected transaction directory")
    children = list(entry.iterdir())
    if len(children) > 20:
        raise UpdateError("unexpected transaction contents")

    def private_file(path):
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_nlink != 1 or
                stat.S_IMODE(info.st_mode) & 0o022):
            raise UpdateError("unsafe transaction file")

    for child in children:
        if child.name in {"old", "new"}:
            info = child.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or
                    stat.S_IMODE(info.st_mode) != 0o700):
                raise UpdateError("unsafe artifact directory")
            artifacts = list(child.iterdir())
            if len(artifacts) > len(PACKAGES):
                raise UpdateError("unexpected transaction artifacts")
            for artifact in artifacts:
                if not any(artifact.name.startswith(name + "_") and artifact.name.endswith(".deb")
                           for name in PACKAGES):
                    raise UpdateError("unexpected transaction artifact")
                private_file(artifact)
        elif (child.name in {"transaction.json", ".journal.lock"} or
              re.fullmatch(r"\.journal-[a-f0-9]{32}", child.name)):
            private_file(child)
        else:
            raise UpdateError("unexpected transaction content")


def cleanup_terminal_transactions(updater_lock, *, now=None, _test_expected_uid=None):
    """Prune only old completed/recovered caches while keeping recent rollback artifacts."""
    owner = 0 if _test_expected_uid is None else _test_expected_uid
    if os.path.lexists(MARKER):
        raise UpdateError("Guardian fence exists; defer update-cache cleanup")
    state = os.lstat(STATE)
    if (not stat.S_ISDIR(state.st_mode) or state.st_uid != owner or
            stat.S_IMODE(state.st_mode) != 0o700):
        raise UpdateError("unsafe update state directory")
    _verify_updater_lock(updater_lock, owner)
    if not getattr(shutil.rmtree, "avoids_symlink_attacks", False):
        raise UpdateError("safe update-cache cleanup is unavailable")
    current = now if now is not None else datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        raise UpdateError("cleanup time must include a timezone")
    retired = STATE / ".retired"
    if os.path.lexists(retired):
        info = os.lstat(retired)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or stat.S_IMODE(info.st_mode) != 0o700:
            raise UpdateError("unsafe retired update directory")
        for leftover in retired.iterdir():
            _validate_artifact_tree(leftover, owner)
            if os.path.lexists(MARKER):
                raise UpdateError("Guardian fence appeared during retired-cache cleanup")
            _purge_retired_transaction(leftover, owner)
    records = []
    for path in STATE.iterdir():
        if path.name == ".updater.lock":
            continue
        if path.name in {".preflight", ".retired"}:
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or stat.S_IMODE(info.st_mode) != 0o700:
                raise UpdateError("unsafe private update directory")
            continue
        _validate_artifact_tree(path, owner)
        kwargs = {} if _test_expected_uid is None else {"_test_expected_uid": owner}
        record = transaction_journal.read(STATE, path.name, **kwargs)
        records.append((path, record, (path / "transaction.json").lstat().st_mtime))
    completed = sorted(((mtime, path.name) for path, record, mtime in records if record["phase"] == "completed"),
                       reverse=True)
    keep = {name for _, name in completed[:3]}
    terminal = {"completed", "aborted", "pre_mutation_recovered"}
    for path, record, mtime in records:
        if record["phase"] not in terminal or path.name in keep:
            continue
        if current.timestamp() - mtime <= 30 * 24 * 3600:
            continue
        if os.path.lexists(MARKER):
            raise UpdateError("Guardian fence appeared during update-cache cleanup")
        _verify_retained_artifacts(path, record["plan"], owner)
        try:
            os.mkdir(retired, 0o700)
            sync_directory(STATE)
        except FileExistsError:
            pass
        retired_info = os.lstat(retired)
        if (not stat.S_ISDIR(retired_info.st_mode) or retired_info.st_uid != owner or
                stat.S_IMODE(retired_info.st_mode) != 0o700):
            raise UpdateError("unsafe retired update directory")
        destination = retired / path.name
        if os.path.lexists(destination):
            raise UpdateError("retired update transaction already exists")
        # Remove a terminal transaction from the active journal namespace
        # durably before pruning its cache. An interrupted delete may leave
        # files under .retired, but cannot erase an active journal in place.
        os.rename(path, destination)
        sync_directory(STATE)
        sync_directory(retired)
        _purge_retired_transaction(destination, owner)


def _verify_retained_artifacts(directory, plan, owner, *, allow_partial=False):
    """Before cache deletion bind each artifact to its immutable journal hash."""
    for subdir, key in (("old", "old_sha256"), ("new", "new_sha256")):
        root = directory / subdir
        files = list(root.iterdir()) if root.exists() else []
        if not allow_partial and len(files) != len(plan["packages"]):
            raise UpdateError("retained package set is incomplete")
        remaining = set(files)
        for package in plan["packages"]:
            matches = [path for path in files if path.name.startswith(package["name"] + "_") and path.name.endswith(".deb")]
            if allow_partial and not matches:
                continue
            if len(matches) != 1 or matches[0] not in remaining:
                raise UpdateError("retained package is unbound to journal")
            path = matches[0]
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_nlink != 1 or
                        stat.S_IMODE(info.st_mode) & 0o022):
                    raise UpdateError("unsafe retained package")
                digest = hashlib.sha256()
                while True:
                    chunk = os.read(fd, 1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                if not hmac.compare_digest(digest.hexdigest(), package[key]):
                    raise UpdateError("retained package differs from journal")
            finally:
                os.close(fd)
            remaining.remove(path)
        if remaining:
            raise UpdateError("unexpected retained package")


def _purge_retired_transaction(directory, owner):
    """Delete only journal-bound retired cache, keeping its journal until last."""
    _validate_artifact_tree(directory, owner)
    record_path = directory / transaction_journal.RECORD
    if not os.path.lexists(record_path):
        # The only safe journal-less residue is the empty lock or an empty dir:
        # the journal is removed after all artifacts and temporary files.
        children = list(directory.iterdir())
        if any(path.name != transaction_journal.LOCK for path in children):
            raise UpdateError("retired transaction lacks its journal; manual review required")
        for path in children:
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_nlink != 1 or
                    stat.S_IMODE(info.st_mode) != 0o600 or info.st_size != 0):
                raise UpdateError("unsafe retired journal lock")
            path.unlink()
        sync_directory(directory)
        directory.rmdir()
        sync_directory(directory.parent)
        return

    parent_fd = transaction_journal._open_txn(directory.parent, directory.name, owner)
    lock_fd = None
    try:
        lock_fd = transaction_journal._lock(parent_fd, owner)
        record = transaction_journal._read(parent_fd, directory.name, owner)
        if record["phase"] not in {"completed", "aborted", "pre_mutation_recovered"}:
            raise UpdateError("nonterminal transaction is retired; manual review required")
        _verify_retained_artifacts(directory, record["plan"], owner, allow_partial=True)
        for subdir in ("old", "new"):
            folder = directory / subdir
            if not folder.exists():
                continue
            for artifact in folder.iterdir():
                artifact.unlink()
                sync_directory(folder)
            folder.rmdir()
            sync_directory(directory)
        for path in directory.iterdir():
            if re.fullmatch(r"\.journal-[a-f0-9]{32}", path.name):
                path.unlink()
                sync_directory(directory)
        # Deleting the plan last preserves hash evidence across interruptions.
        record_path.unlink()
        sync_directory(directory)
        (directory / transaction_journal.LOCK).unlink()
        sync_directory(directory)
    finally:
        if lock_fd is not None:
            os.close(lock_fd)
        os.close(parent_fd)
    directory.rmdir()
    sync_directory(directory.parent)


def assert_no_unresolved_journals():
    """Prevent a new package mutation while a previous transaction is ambiguous."""
    terminal = {"completed", "aborted", "pre_mutation_recovered"}
    for entry in STATE.iterdir():
        info = entry.lstat()
        if entry.name == ".updater.lock":
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or
                    stat.S_IMODE(info.st_mode) != 0o600):
                raise UpdateError("unsafe global updater lock")
            continue
        if entry.name in {".preflight", ".retired"}:
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
                raise UpdateError("unsafe update preflight directory")
            continue
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise UpdateError("unexpected update state entry; manual review required")
        if not transaction_journal.IDENTIFIER.fullmatch(entry.name):
            raise UpdateError("unexpected update transaction name; manual review required")
        try:
            record = transaction_journal.read(STATE, entry.name)
        except FileNotFoundError:
            # A directory without a journal could be a crash while downloading
            # preflight artifacts or damage to a later transaction. Do not
            # infer which case occurred without a separate durable record.
            raise UpdateError("incomplete update state; manual review required") from None
        if record["phase"] not in terminal:
            raise UpdateError("previous Docker update needs reconciliation")


def assert_noop_safe():
    """Never report a clean no-op while an update fence or journal remains."""
    if os.path.lexists(MARKER):
        raise UpdateError("Guardian migration fence exists; review before reporting clean")
    if not os.path.lexists(STATE):
        return
    info = os.lstat(STATE)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise UpdateError("unsafe update state directory")
    fd = acquire_updater_lock()
    try:
        if os.path.lexists(MARKER):
            raise UpdateError("Guardian migration fence exists; review before reporting clean")
        assert_no_unresolved_journals()
        cleanup_terminal_transactions(fd)
        preflight = STATE / ".preflight"
        if os.path.lexists(preflight):
            cleanup_preflight(preflight, fd)
        if os.path.lexists(MARKER):
            raise UpdateError("Guardian migration fence appeared during no-op check")
    finally:
        os.close(fd)


def require_recent_backup(max_age_seconds=26 * 3600):
    """Check a recent encrypted backup and its checksum before changing Docker.

    Integrity of this encrypted file does not prove that a restore will work.
    """
    root = Path("/var/backups/mail-guardian/pilot")
    candidates = sorted(root.glob("*.age"), key=lambda p: p.stat().st_mtime, reverse=True)
    for backup in candidates:
        info = backup.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1:
            continue
        if not 0 <= time.time() - info.st_mtime <= max_age_seconds:
            continue
        receipt = backup.with_name(backup.name + ".sha256")
        if receipt.is_symlink() or not receipt.is_file():
            continue
        row = receipt.read_text().strip().split(None, 1)
        if len(row) != 2 or not re.fullmatch(r"[a-f0-9]{64}", row[0]) or row[1].lstrip("*") != backup.name:
            continue
        digest = hashlib.sha256()
        with backup.open("rb") as f:
            for block in iter(lambda: f.read(1024 * 1024), b""):
                digest.update(block)
        if hmac.compare_digest(digest.hexdigest(), row[0]):
            return
    raise UpdateError("no recent verified encrypted backup; defer update")


def apply(baseline, targets):
    if os.geteuid() != 0:
        raise UpdateError("apply requires root")
    if not all(unit_active(t) for t in TIMERS):
        raise UpdateError("Guardian schedules are not both active; defer update")
    if any(unit_busy(u) for u in WORKERS) or os.path.lexists(MARKER):
        raise UpdateError("Guardian or another migration is active")
    if run(["dpkg", "--audit"]).stdout.strip():
        raise UpdateError("dpkg is not in a clean state")
    require_recent_backup()
    before = container_snapshot()
    health(before)
    state_created = False
    try:
        os.mkdir(STATE, 0o700)
        state_created = True
    except FileExistsError:
        pass
    state_info = os.lstat(STATE)
    if (not stat.S_ISDIR(state_info.st_mode) or state_info.st_uid != 0 or
            stat.S_IMODE(state_info.st_mode) != 0o700):
        raise UpdateError("unsafe update state directory")
    if state_created:
        sync_directory(STATE.parent)
    updater_lock = acquire_updater_lock()
    try:
        return apply_locked(baseline, targets, before, updater_lock)
    finally:
        os.close(updater_lock)


def apply_locked(baseline, targets, before, updater_lock):
    """Called only while the verified global updater lock remains held."""
    assert_no_unresolved_journals()
    cleanup_terminal_transactions(updater_lock)
    preflight = STATE / ".preflight"
    try:
        os.mkdir(preflight, 0o700)
        sync_directory(STATE)
    except FileExistsError:
        pass
    info = os.lstat(preflight)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise UpdateError("unsafe update preflight directory")
    cleanup_preflight(preflight, updater_lock)
    if shutil.disk_usage(STATE).free < 2 * 1024**3:
        raise UpdateError("less than 2 GiB free; defer update")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    directory = Path(tempfile.mkdtemp(prefix=timestamp + "-", dir=preflight))
    sync_directory(preflight)
    transaction = directory.name
    old_dir, new_dir = directory / "old", directory / "new"
    old_dir.mkdir(mode=0o700)
    new_dir.mkdir(mode=0o700)
    sync_directory(directory)
    rollback = save_packages(old_dir, baseline, targets)
    packages = save_packages(new_dir, targets, targets)
    sync_directory(old_dir)
    sync_directory(new_dir)
    sync_directory(directory)
    fence = None
    frontend_lock = None
    marker = None
    mutation_started = False
    recovered = False
    try:
        fence = acquire_fence()
        if any(unit_busy(u) for u in WORKERS) or os.path.lexists(MARKER):
            raise UpdateError("Guardian or another migration raced maintenance")
        frontend_lock = acquire_frontend_lock()
        current, now_targets, _ = candidates()
        if current != baseline or now_targets != targets:
            raise UpdateError("package candidates changed; defer")
        simulation(targets, baseline)
        if container_snapshot() != before:
            raise UpdateError("container state changed; defer")
        inventory = installed_inventory()
        record = initialize_journal(directory, baseline, targets, rollback, packages, inventory, before)
        published = STATE / transaction
        if os.path.lexists(published):
            raise UpdateError("update transaction already exists")
        # Publish the already complete, synced journal and artifacts as one
        # same-filesystem rename. A crash during downloads leaves only an
        # ignored preflight directory and cannot strand a production fence.
        os.rename(directory, published)
        sync_directory(preflight)
        sync_directory(STATE)
        directory = published
        rollback = {name: (str(directory / "old" / Path(path).name), digest)
                    for name, (path, digest) in rollback.items()}
        packages = {name: (str(directory / "new" / Path(path).name), digest)
                    for name, (path, digest) in packages.items()}
        record = advance_journal(record, "fence_creating")
        marker = create_marker(transaction)
        marker_inode = marker_identity(marker)
        record = advance_journal(record, "fenced")
        assert_frontend_lock_held(frontend_lock)
        # This write-ahead transition must be durable before dpkg can start.
        # An interruption from this point onward requires manual recovery.
        record = advance_journal(record, "mutation_pending")
        mutation_started = True
        try:
            # Install only the exact verified artifacts. Unlike an APT install,
            # dpkg cannot resolve and add unexpected dependencies if APT state
            # changed after simulation. A dependency failure remains fenced.
            if not all(hmac.compare_digest(hashlib.sha256(Path(path).read_bytes()).hexdigest(), digest)
                       for path, digest in packages.values()):
                raise UpdateError("downloaded package hash changed")
            assert_frontend_lock_held(frontend_lock)
            run(["dpkg", "--refuse-downgrade", "--force-confdef", "--force-confold", "-i"] +
                [entry[0] for entry in packages.values()], timeout=900, frontend_locked=True)
            assert_frontend_lock_held(frontend_lock)
            if not inventory_matches(inventory, installed_inventory(), targets):
                raise UpdateError("installed package changes differ from transaction")
            health(before)
            if run(["dpkg", "--audit"]).stdout.strip():
                raise UpdateError("dpkg audit after update failed")
            record = advance_journal(record, "verified")
            record = advance_journal(record, "unfence_intent")
            recovered = True
        except subprocess.TimeoutExpired:
            # A timed-out package process may have partially changed dpkg state.
            # Do not race it with rollback; leave the durable fence in place.
            raise UpdateError("package transaction timed out; Guardian remains fenced")
        except (UpdateError, OSError):
            # A downgrade can race other package operations or leave persisted
            # model data incompatible. Retain the artifacts and fence; do not
            # attempt a package downgrade without qualified recovery.
            raise UpdateError("update failed; Guardian remains fenced for recovery")
        finally:
            if recovered and marker is not None:
                clear_own_marker(marker, expected_identity=marker_inode)
                record = advance_journal(record, "completed")
    finally:
        if frontend_lock is not None:
            os.close(frontend_lock)
        if fence is not None:
            os.close(fence)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--simulate", action="store_true")
    mode.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        if args.apply:
            run(["apt-get", "-o", "APT::Update::Error-Mode=any", "update"], timeout=300)
        baseline, targets, skipped = candidates()
        if args.simulate or args.apply:
            simulation(targets, baseline)
        if args.apply:
            if targets:
                apply(baseline, targets)
            else:
                assert_noop_safe()
        print(json.dumps({"mode": "apply" if args.apply else "simulate" if args.simulate else "check",
                          "installed": baseline, "patch_candidates": targets,
                          "deferred_candidates": skipped, "application_attempted": bool(args.apply and targets)}))
        return 2 if skipped else 0
    except (UpdateError, OSError, subprocess.TimeoutExpired, RuntimeError) as exc:
        print(json.dumps({"error": str(exc), "state": "inspect service journal and migration-pending before recovery"}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
