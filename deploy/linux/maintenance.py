#!/usr/bin/python3 -I
"""Fixed-operation root dispatcher. Never accepts paths from the mailbox worker."""

import fcntl
import contextlib
import grp
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request

DOCKER = "/usr/bin/docker"
INSTANCE_BASE = Path("/etc/mail-guardian")
ADMIN_RUNTIME_BASE = Path("/var/lib/mail-guardian-admin")
RSPAMD_IMAGE = "rspamd/rspamd:4.1.2@sha256:15dfe447f8913516c4ff24933a0727aff53d88bf38ef1937fb74f5152568f496"
# This pinned image runs Rspamd as UID/GID 11333. The controller file holds
# only the generated password hash, never the original credential. The host
# directory remains root-only; the file is mounted directly into the image.
RSPAMD_GID = 11333
OPERATIONS = frozenset(("up", "down", "status", "deep-check", "check-storage", "check-persistence", "export-redis"))
MAX_TEXT = 64 << 10
MAX_RDB = 128 << 20
ENVIRONMENT = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LANG": "C.UTF-8"}
STORAGE_ERRORS = re.compile(r"I/O error(?:,| on)|EXT4-fs.*(?:failed to convert unwritten|Aborting journal|Remounting filesystem read-only)|EXT4-fs error|XFS.*(?:Corruption|I/O error|Filesystem has been shut down)|BTRFS.*(?:error|corrupt)", re.IGNORECASE)


class MaintenanceError(Exception):
    pass


def parse_request(args, euid, sudo_user):
    if len(args) != 2:
        raise MaintenanceError("expected instance and fixed operation")
    instance, operation = args
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", instance):
        raise MaintenanceError("invalid instance")
    if operation not in OPERATIONS:
        raise MaintenanceError("unsupported maintenance operation")
    if euid != 0 or sudo_user not in (None, "root", "mg-" + instance):
        raise MaintenanceError("maintenance authorization rejected")
    return instance, operation


def trusted_path(path, directory=False, private=False):
    """lstat every ancestor; worker-controlled symlinks can never reach root."""
    path = Path(path)
    if not path.is_absolute():
        raise MaintenanceError("administrator path must be absolute")
    for entry in reversed((path,) + tuple(path.parents)):
        info = entry.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise MaintenanceError("unsafe administrator path")
        if entry != path and not stat.S_ISDIR(info.st_mode):
            raise MaintenanceError("unsafe administrator parent")
    info = path.lstat()
    if directory != stat.S_ISDIR(info.st_mode):
        raise MaintenanceError("incorrect administrator path type")
    if not directory and not stat.S_ISREG(info.st_mode):
        raise MaintenanceError("administrator file must be regular")
    if private and info.st_mode & 0o077:
        raise MaintenanceError("administrator secret is not private")
    return path


def private_runtime(instance):
    # Docker restarts containers before Guardian's next scheduled run. A file
    # bind under /run would disappear at boot; legacy -v/Compose bind handling
    # can recreate the missing source as a directory and prevent startup.
    # Retain only the generated controller hash/fingerprint in this root-only
    # persistent tree. Runtime locks continue to live separately under /run.
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", instance):
        raise MaintenanceError("invalid instance")
    trusted_path(ADMIN_RUNTIME_BASE.parent, directory=True)
    ADMIN_RUNTIME_BASE.mkdir(mode=0o700, exist_ok=True)
    trusted_path(ADMIN_RUNTIME_BASE, directory=True, private=True)
    runtime = ADMIN_RUNTIME_BASE / instance
    runtime.mkdir(mode=0o700, exist_ok=True)
    trusted_path(runtime, directory=True, private=True)
    sync_directory(runtime)
    sync_directory(ADMIN_RUNTIME_BASE)
    sync_directory(ADMIN_RUNTIME_BASE.parent)
    return runtime


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@contextlib.contextmanager
def shared_migration_fence(instance):
    """Hold the administrator-owned fence through one complete operation.

    The administrator performing a migration must hold the same file's
    exclusive lock across creating/removing the persistent pending marker AND
    the entire publication. Older helpers and workers do not honor this fence.
    """
    root = INSTANCE_BASE / instance
    trusted_path(root, directory=True)
    path = root / "migration.lock"
    info = trusted_path(path).lstat()
    try:
        group = grp.getgrnam("mg-" + instance)
    except KeyError:
        raise MaintenanceError("migration fence group unavailable") from None
    if (info.st_gid != group.gr_gid or stat.S_IMODE(info.st_mode) != 0o640 or
            info.st_nlink != 1):
        raise MaintenanceError("unsafe migration fence")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as lock:
        opened = os.fstat(lock.fileno())
        if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != 0 or
                opened.st_gid != group.gr_gid or stat.S_IMODE(opened.st_mode) != 0o640 or
                opened.st_nlink != 1 or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)):
            raise MaintenanceError("unsafe migration fence")
        try:
            fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            raise MaintenanceError("migration is in progress") from None
        try:
            (root / "migration-pending").lstat()
        except FileNotFoundError:
            pass
        else:
            # The marker's mere presence blocks even if its contents or type
            # are malformed; it can only be reconciled by an administrator.
            raise MaintenanceError("migration needs administrator recovery")
        yield


def run(args, *, timeout=30, max_output=MAX_TEXT, input_data=None):
    # Disk-backed capture bounds memory; polling kills oversized processes before
    # returning any bytes. Only sanitized fixed argv is ever used.
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err, tempfile.TemporaryFile() as incoming:
        if input_data is not None:
            incoming.write(input_data)
            incoming.seek(0)
        proc = subprocess.Popen(args, stdin=incoming if input_data is not None else subprocess.DEVNULL,
                                stdout=out, stderr=err, env=ENVIRONMENT, close_fds=True)
        deadline = time.monotonic() + timeout
        try:
            while proc.poll() is None:
                if out.tell() > max_output or err.tell() > MAX_TEXT:
                    raise MaintenanceError("maintenance output exceeded limit")
                if time.monotonic() >= deadline:
                    raise MaintenanceError("maintenance operation timed out")
                time.sleep(0.05)
            if out.tell() > max_output or err.tell() > MAX_TEXT:
                raise MaintenanceError("maintenance output exceeded limit")
            if proc.returncode != 0:
                # Container and command diagnostics can contain sensitive values.
                raise MaintenanceError("maintenance dependency returned failure")
            out.seek(0)
            return out.read(max_output + 1)
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait()


class Dispatcher:
    def __init__(self, instance):
        self.instance = instance
        self.root = Path("/etc/mail-guardian") / instance
        self.deploy = self.root / "deploy"
        trusted_path(DOCKER)
        trusted_path(self.deploy, directory=True)
        # Docker Compose processes included configuration and bind-mount paths.
        # All installed entries must remain administrator-owned and immutable.
        for base, dirs, files in os.walk(self.deploy, followlinks=False):
            for name in dirs:
                trusted_path(Path(base) / name, directory=True)
            for name in files:
                trusted_path(Path(base) / name)
        marker = trusted_path("/etc/mail-guardian/instance").read_text().strip()
        if marker != instance:
            raise MaintenanceError("instance does not match provisioned host")
        self.runtime = private_runtime(instance)
        self.env = dict(ENVIRONMENT, GUARDIAN_RUNTIME_DIR=str(self.runtime))

    def compose(self, *args, **kwargs):
        # Fixed env is passed by temporarily extending the fixed environment;
        # no DOCKER_HOST/CONTEXT/COMPOSE_FILE from the caller survives.
        previous = dict(ENVIRONMENT)
        ENVIRONMENT["GUARDIAN_RUNTIME_DIR"] = str(self.runtime)
        try:
            return run([DOCKER, "--host", "unix:///var/run/docker.sock", "compose", "--project-name", "mail-guardian-" + self.instance,
                        "--project-directory", str(self.deploy), "--file", str(self.deploy / "compose.yaml"), *args], **kwargs)
        finally:
            ENVIRONMENT.clear()
            ENVIRONMENT.update(previous)

    def storage(self):
        logs = run(["/usr/bin/dmesg", "--level=err,warn", "--notime"], max_output=8 << 20)
        if STORAGE_ERRORS.search(logs.decode("utf-8", "replace")):
            raise MaintenanceError("kernel reports storage errors; administrator investigation required")
        # Never open or write anything beneath worker-owned state as root.
        for path in ("/var/lib/docker", "/var/lib/mail-guardian"):
            trusted_path(path, directory=True)
            space = os.statvfs(path)
            if space.f_flag & getattr(os, "ST_RDONLY", 1) or space.f_bavail * space.f_frsize < 2 << 30:
                raise MaintenanceError("insufficient or read-only host storage")

    def persistence(self):
        self.storage()
        fields = {}
        for line in self.compose("exec", "-T", "redis", "redis-cli", "--raw", "INFO", "persistence").decode().splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                fields[key] = value.strip()
        if any(fields.get(key) != value for key, value in {"aof_enabled": "1", "aof_last_write_status": "ok", "rdb_last_bgsave_status": "ok"}.items()):
            raise MaintenanceError("Redis persistence is unhealthy")
        fsync = self.compose("exec", "-T", "redis", "redis-cli", "--raw", "CONFIG", "GET", "appendfsync").decode().splitlines()
        if fsync != ["appendfsync", "always"]:
            raise MaintenanceError("Redis appendfsync must be always")

    def controller(self):
        self.require_unmapped_docker()
        source = trusted_path(self.root / "credentials" / "rspamd-password", private=True)
        raw = source.read_bytes()
        password = raw.removesuffix(b"\n").removesuffix(b"\r")
        if not password or len(raw) > 16384 or any(x in password for x in (b"\n", b"\r", b"\0")):
            raise MaintenanceError("invalid controller credential")
        folder = self.runtime / "rspamd"
        folder.mkdir(mode=0o700, exist_ok=True)
        trusted_path(folder, directory=True, private=True)
        sync_directory(self.runtime)
        target = folder / "worker-controller.inc"
        fingerprint = folder / ".credential-sha256"
        digest = hashlib.sha256(password).hexdigest()
        # Validate even partial old state, including dangling symlinks. An old
        # root:root 0600 file is regenerated instead of being reused: it is not
        # readable by the unprivileged Rspamd process inside the bind mount.
        target_exists = os.path.lexists(target)
        fingerprint_exists = os.path.lexists(fingerprint)
        if target_exists:
            info = trusted_path(target).lstat()
        if fingerprint_exists:
            trusted_path(fingerprint, private=True)
        if target_exists and fingerprint_exists and info.st_size <= 4096 and fingerprint.stat().st_size <= 256:
            # Bind the private password fingerprint to the exact controller
            # file. If a crash publishes a new file but not its fingerprint,
            # even reverting the password cannot make stale metadata match.
            controller_digest = hashlib.sha256(target.read_bytes()).hexdigest()
            expected_fingerprint = digest + "\n" + controller_digest + "\n"
            if (info.st_gid == RSPAMD_GID and stat.S_IMODE(info.st_mode) == 0o640 and
                    fingerprint.read_text() == expected_fingerprint):
                return False
        # Rspamd 4.1.2's registered Lua pw_encrypt calls its native Catena
        # implementation. stdin avoids password argv even inside the container.
        # Source: https://github.com/rspamd/rspamd/blob/4.1.2/src/rspamadm/pw.c
        hashed = run([DOCKER, "--host", "unix:///var/run/docker.sock", "run", "--rm", "--interactive", "--network", "none",
                      "--read-only", "--cap-drop", "ALL", "--entrypoint", "rspamadm", RSPAMD_IMAGE,
                      "lua", "--exec", 'local password = io.read("*l"); assert(password); print(rspamadm.pw_encrypt(password))'],
                     input_data=password + b"\n", timeout=60).strip()
        if not re.fullmatch(rb"\$[A-Za-z0-9$./+=_-]{20,512}", hashed):
            raise MaintenanceError("invalid controller password hash")
        content = (b'bind_socket = "*:11334";\npassword = "' + hashed + b'";\nenable_password = "' + hashed +
                   b'";\nsecure_ip = ["127.0.0.1", "::1"];\n')
        fd, stage = tempfile.mkstemp(prefix=".controller-", dir=folder)
        try:
            with os.fdopen(fd, "wb") as file:
                file.write(content)
                file.flush()
                os.fchown(file.fileno(), 0, RSPAMD_GID)
                os.fchmod(file.fileno(), 0o640)
                os.fsync(file.fileno())
            os.replace(stage, target)
            sync_directory(folder)
        finally:
            if os.path.exists(stage):
                os.unlink(stage)
        fd, stage = tempfile.mkstemp(prefix=".fingerprint-", dir=folder)
        try:
            with os.fdopen(fd, "w") as file:
                file.write(digest + "\n" + hashlib.sha256(content).hexdigest() + "\n")
                file.flush()
                os.fsync(file.fileno())
            os.replace(stage, fingerprint)
            sync_directory(folder)
        finally:
            if os.path.exists(stage):
                os.unlink(stage)
        return True

    def require_unmapped_docker(self):
        # Remapping changes the host GID required for the image's 11333 group.
        # Do not guess that mapping or make the password hash world-readable.
        raw = run([DOCKER, "--host", "unix:///var/run/docker.sock", "info", "--format", "{{json .SecurityOptions}}"])
        try:
            options = json.loads(raw)
            if not isinstance(options, list) or not all(isinstance(item, str) for item in options):
                raise ValueError()
            if any(item.split(",", 1)[0] in ("name=userns", "name=rootless") for item in options):
                raise ValueError()
        except (ValueError, TypeError):
            raise MaintenanceError("Docker user namespace remapping is unsupported") from None

    def ping(self):
        # Disable redirects and proxies so a response cannot redirect a root
        # request beyond the two fixed loopback endpoints.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        for port in (11333, 11334):
            with client.open("http://127.0.0.1:" + str(port) + "/ping", timeout=8) as response:
                if response.status != 200 or response.read(1025).strip().lower() != b"pong":
                    raise MaintenanceError("Rspamd readiness failed")

    def dispatch(self, operation):
        if operation == "check-storage":
            self.storage()
        elif operation == "check-persistence":
            self.persistence()
        elif operation == "export-redis":
            self.persistence()
            return self.compose("exec", "-T", "redis", "redis-cli", "--rdb", "-", timeout=90, max_output=MAX_RDB)
        elif operation == "down":
            self.compose("down", "--remove-orphans", timeout=180)
        elif operation == "up":
            self.storage()
            changed = self.controller()
            self.compose("config", "--quiet")
            args = ["up", "--detach", "--wait", "--remove-orphans"]
            if changed:
                args.append("--force-recreate")
            self.compose(*args, timeout=180)
            self.persistence()
            self.ping()
        elif operation in ("status", "deep-check"):
            status = self.compose("ps", "--format", "json")
            try:
                text = status.decode()
                rows = json.loads(text) if text.lstrip().startswith("[") else [json.loads(line) for line in text.splitlines() if line.strip()]
                if not isinstance(rows, list) or len(rows) != 3 or {row.get("Service") for row in rows} != {"redis", "rspamd", "unbound"}:
                    raise ValueError("missing services")
                # Redis/Unbound have explicit Compose healthchecks. Rspamd
                # readiness is proven by fixed /ping checks below; its pinned
                # image need not expose a Docker HEALTHCHECK.
                if any(row.get("State") != "running" or
                       (row.get("Service") != "rspamd" and row.get("Health") != "healthy") or
                       (row.get("Service") == "rspamd" and row.get("Health", "") not in ("", "healthy")) for row in rows):
                    raise ValueError("unhealthy services")
            except (ValueError, TypeError, AttributeError):
                raise MaintenanceError("container readiness failed")
            self.ping()
            if operation == "deep-check":
                self.persistence()
                self.compose("config", "--quiet")
                self.compose("exec", "-T", "rspamd", "rspamadm", "configtest")
                if self.compose("exec", "-T", "redis", "redis-cli", "--raw", "ping").strip() != b"PONG":
                    raise MaintenanceError("Redis readiness failed")
                self.compose("exec", "-T", "unbound", "drill-hc", "@127.0.0.1", "dnssec.works")
            return status
        return b"ok\n"


def main():
    instance, operation = parse_request(sys.argv[1:], os.geteuid(), os.environ.get("SUDO_USER"))
    os.umask(0o077)
    # Order: migration fence -> helper lock. A normal worker also holds a
    # shared migration fence; the administrator needs an exclusive one.
    with shared_migration_fence(instance):
        trusted_path("/run", directory=True)
        lock_path = "/run/mail-guardian-maintenance-" + instance + ".lock"
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "r+b") as lock:
            info = os.fstat(lock.fileno())
            if info.st_uid != 0 or info.st_mode & 0o077 or not stat.S_ISREG(info.st_mode):
                raise MaintenanceError("unsafe maintenance lock")
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise MaintenanceError("another maintenance operation is running")
            sys.stdout.buffer.write(Dispatcher(instance).dispatch(operation))


if __name__ == "__main__":
    try:
        main()
    except (MaintenanceError, OSError, ValueError, UnicodeError, urllib.error.URLError):
        # Do not emit paths, container logs, credentials or command arguments.
        print("Mail Guardian maintenance failed; administrator diagnostics required.", file=sys.stderr)
        sys.exit(1)
