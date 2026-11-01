#!/usr/bin/env python3
"""Upgrade the existing empty, disabled VPS pilot, preserving its old release.

This is deliberately a one-time bootstrap, not an updater for a live mailbox.
It refuses configuration, credentials, state, project containers or a timer.
An interruption leaves migration-pending and the timer disabled for inspection.
"""

import argparse
import datetime
import contextlib
import fcntl
import grp
import hashlib
import importlib.util
import json
import os
import pwd
import re
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


# Importing the verified installer must not add unlisted bytecode to releases.
sys.dont_write_bytecode = True

ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LANG": "C.UTF-8"}


def run(args, expected=0):
    result = subprocess.run(args, capture_output=True, stdin=subprocess.DEVNULL,
                            env=ENV, timeout=60, check=False)
    if result.returncode != expected:
        raise RuntimeError("bootstrap validation failed: " + args[0])
    return result.stdout


def atomic_bytes(target, data, mode=0o644, gid=0):
    fd, name = tempfile.mkstemp(prefix=".bootstrap-", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            os.fchown(stream.fileno(), 0, gid)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, target)
        sync_directory(target.parent)
    finally:
        if os.path.lexists(name):
            os.unlink(name)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def trusted(path, directory=False):
    path = Path(path)
    if not path.is_absolute() or str(path) != os.path.normpath(path):
        raise ValueError("administrator path must be clean and absolute")
    for parent in reversed([path, *path.parents]):
        info = parent.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise ValueError("unsafe administrator path")
        if parent != path and not stat.S_ISDIR(info.st_mode):
            raise ValueError("unsafe administrator ancestor")
    info = path.lstat()
    if directory != stat.S_ISDIR(info.st_mode):
        raise ValueError("required administrator path type unavailable")
    if not directory and not stat.S_ISREG(info.st_mode):
        raise ValueError("administrator file must be regular")


def assert_empty(root, owner=0, gid=None):
    # Do not traverse a worker-owned tree as root. An empty pilot has no child
    # objects at all, and the top-level inode must be a real private directory.
    info = root.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_mode & 0o077
            or (gid is not None and info.st_gid != gid)):
        raise ValueError("unsafe empty-pilot directory")
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError("empty-pilot directory changed")
        if os.listdir(fd):
            raise ValueError("pilot contains application files; live upgrade is unsupported")
    finally:
        os.close(fd)


def verify_package(root, expected):
    """Verify bytes before executing candidate Python; accepts legacy manifests."""
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("a trusted manifest SHA-256 is required")
    trusted(root, directory=True)
    manifest = root / "SHA256SUMS"
    trusted(manifest)
    if digest(manifest) != expected:
        raise ValueError("release manifest digest mismatch")
    entries = {}
    for line in manifest.read_text().splitlines():
        expected_file, separator, name = line.partition("  ")
        relative = Path(name)
        if (not separator or not re.fullmatch(r"[0-9a-f]{64}", expected_file)
                or not name or str(relative) != name or relative.is_absolute()
                or ".." in relative.parts or name in entries or name == "SHA256SUMS"):
            raise ValueError("invalid release manifest")
        target = root / relative
        trusted(target)
        if digest(target) != expected_file:
            raise ValueError("release file checksum mismatch")
        entries[name] = expected_file
    actual = set()
    for target in root.rglob("*"):
        trusted(target, directory=target.is_dir() and not target.is_symlink())
        if target.is_file() and target != manifest:
            actual.add(str(target.relative_to(root)))
    if actual != set(entries):
        raise ValueError("release has missing or unlisted files")
    return entries


@contextlib.contextmanager
def exclusive_root_lock(path):
    trusted(path.parent, directory=True)
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise ValueError("unsafe bootstrap serialization lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def assert_stopped():
    for unit in ("mail-guardian@pilot.timer", "mail-guardian@pilot.service"):
        if run(["/usr/bin/systemctl", "is-active", unit], expected=3).strip() != b"inactive":
            raise ValueError("pilot service or timer is not inactive")
    if run(["/usr/bin/systemctl", "is-enabled", "mail-guardian@pilot.timer"], expected=1).strip() != b"disabled":
        raise ValueError("pilot timer is not disabled")
    run(["/usr/bin/pgrep", "-u", "mg-pilot"], expected=1)
    for args in (("ps", "-aq"), ("volume", "ls", "-q"), ("network", "ls", "-q")):
        projects = run(["/usr/bin/docker", "--host", "unix:///var/run/docker.sock", *args,
                        "--filter", "label=com.docker.compose.project=mail-guardian-pilot"])
        if projects.strip():
            raise ValueError("pilot Docker project resources already exist")


def sync_tree(root):
    for path in root.rglob("*"):
        if path.is_file():
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
    for path in sorted((p for p in root.rglob("*") if p.is_dir()),
                       key=lambda p: len(p.parts), reverse=True):
        sync_directory(path)
    sync_directory(root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--expected-installed-manifest", required=True)
    parser.add_argument("--expected-release-manifest", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    if os.geteuid() != 0:
        raise ValueError("root required")
    with exclusive_root_lock(Path("/run/mail-guardian-provision.lock")):
        upgrade(args)


def upgrade(args):
    release = args.release
    candidate_files = verify_package(release, args.expected_release_manifest)
    required = {"guardian", "guardian-recovery", "install.py", "maintenance.py", "VERSION",
                "mail-guardian@.service", "mail-guardian@.timer", "check_host.py"}
    if not required <= set(candidate_files):
        raise ValueError("candidate is missing required runtime files")
    spec = importlib.util.spec_from_file_location("guardian_installer", release / "install.py")
    installer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installer)
    installer.verify_package(release)
    current = Path("/opt/mail-guardian/current")
    trusted(current.parent, directory=True)
    current_info = current.lstat()
    if not stat.S_ISLNK(current_info.st_mode) or current_info.st_uid != 0:
        raise ValueError("current release must be an administrator-owned symlink")
    old = current.resolve(strict=True)
    if old.parent != Path("/opt/mail-guardian/releases"):
        raise ValueError("unexpected installed release")
    old_files = verify_package(old, args.expected_installed_manifest)
    installer.verify_package(old)
    if {k: v for k, v in old_files.items() if k.startswith("deploy/")} != {
            k: v for k, v in candidate_files.items() if k.startswith("deploy/")}:
        raise ValueError("deployment tree changed; this bootstrap does not replace local deployment configuration")
    trusted(Path("/usr/local/libexec/mail-guardian-maintenance"))
    for unit in ("mail-guardian@.service", "mail-guardian@.timer"):
        installed = Path("/etc/systemd/system") / unit
        trusted(installed)
        if digest(installed) != old_files[unit]:
            raise ValueError("installed unit differs from reviewed release")
    if digest(Path("/usr/local/libexec/mail-guardian-maintenance")) != digest(old / "maintenance.py"):
        raise ValueError("installed helper differs from reviewed release")
    config = Path("/etc/mail-guardian/pilot")
    trusted(config, directory=True)
    if (Path("/etc/mail-guardian/instance").read_text().strip() != "pilot" or
            (config / "config.toml").exists() or os.path.lexists(config / "config.toml") or
            os.path.lexists(config / "migration-pending")):
        raise ValueError("pilot is configured or needs recovery")
    trusted(Path("/etc/mail-guardian/instance"))
    expected_deploy = {k[len("deploy/"):]: v for k, v in old_files.items() if k.startswith("deploy/")}
    deploy = config / "deploy"
    trusted(deploy, directory=True)
    actual_deploy = {}
    for item in deploy.rglob("*"):
        trusted(item, directory=item.is_dir() and not item.is_symlink())
        if item.is_file():
            actual_deploy[str(item.relative_to(deploy))] = digest(item)
    if actual_deploy != expected_deploy:
        raise ValueError("installed deployment tree differs from reviewed release")
    trusted(config / "credentials", directory=True)
    worker = pwd.getpwnam("mg-pilot")
    gid = grp.getgrnam("mg-pilot").gr_gid
    data = Path("/var/lib/mail-guardian/pilot")
    trusted(data.parent, directory=True)
    if (worker.pw_uid == 0 or worker.pw_gid != gid or worker.pw_dir != str(data)
            or worker.pw_shell not in ("/usr/sbin/nologin", "/sbin/nologin")
            or any(g.gr_gid != gid and "mg-pilot" in g.gr_mem for g in grp.getgrall())):
        raise ValueError("worker account policy changed")
    assert_empty(config / "credentials")
    assert_empty(data, worker.pw_uid, gid)
    assert_stopped()
    lock_path = config / "migration.lock"
    if not os.path.lexists(lock_path):
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
        os.fchown(fd, 0, gid)
        os.fchmod(fd, 0o640)
        os.fsync(fd)
        os.close(fd)
        sync_directory(config)
    fd = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != gid or
                stat.S_IMODE(info.st_mode) != 0o640 or info.st_nlink != 1):
            raise ValueError("unsafe migration lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with exclusive_root_lock(Path("/run/mail-guardian-maintenance-pilot.lock")):
            apply_upgrade(args, release, installer, old, config, data, worker, gid)
    finally:
        os.close(fd)


def apply_upgrade(args, release, installer, old, config, data, worker, gid):
    # Recheck after obtaining every lock: older helpers do not take the
    # migration fence and may have finished just before its lock was held.
    assert_stopped()
    assert_empty(config / "credentials")
    assert_empty(data, worker.pw_uid, gid)
    if os.path.lexists(config / "migration-pending") or os.path.lexists(Path("/etc/mail-guardian/pilot-update-pending")):
        raise ValueError("a previous bootstrap requires inspection")
    if Path("/opt/mail-guardian/current").resolve(strict=True) != old:
        raise ValueError("current release changed")
    version = (release / "VERSION").read_text().strip()
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[.-][A-Za-z0-9]+)*", version):
        raise ValueError("invalid release version")
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_root = Path("/var/backups/mail-guardian")
    trusted(backup_root.parent, directory=True)
    if not os.path.lexists(backup_root):
        backup_root.mkdir(mode=0o700)
        sync_directory(backup_root.parent)
    trusted(backup_root, directory=True)
    archive = backup_root / ("bootstrap-" + now)
    archive.mkdir(mode=0o700)
    sync_directory(backup_root)
    for target in [Path("/usr/local/libexec/mail-guardian-maintenance"),
                   *[Path("/etc/systemd/system") / item for item in
                     ("mail-guardian@.service", "mail-guardian@.timer")]]:
        trusted(target)
        shutil.copy2(target, archive / target.name)
    manifest = digest(release / "SHA256SUMS")
    name = version + "-streamlined-" + manifest[:16]
    destination = Path("/opt/mail-guardian/releases") / name
    if destination.exists() or destination.is_symlink():
        raise ValueError("new release destination already exists")
    record = {"started_utc": now, "previous_release": str(old), "new_release": str(destination),
              "old_manifest_sha256": args.expected_installed_manifest,
              "new_manifest_sha256": manifest, "application_state": "empty", "scheduling": "disabled"}
    atomic_bytes(config / "migration-pending", json.dumps(record).encode(), 0o640, gid)
    shutil.copytree(release, destination, symlinks=False)
    for path in [destination, *destination.rglob("*")]:
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError("unsupported release entry")
        os.chown(path, 0, 0)
        executable = path.is_dir() or path.name in ("guardian", "guardian-recovery", "install.sh", "install.py", "maintenance.py")
        os.chmod(path, 0o755 if executable else 0o644)
    installer.verify_package(destination)
    sync_tree(destination)
    sync_directory(destination.parent)
    atomic_bytes(Path("/usr/local/libexec/mail-guardian-maintenance"),
                 (destination / "maintenance.py").read_bytes(), 0o755)
    for unit in ("mail-guardian@.service", "mail-guardian@.timer"):
        atomic_bytes(Path("/etc/systemd/system") / unit, (destination / unit).read_bytes())
    link = Path("/opt/mail-guardian/.current-" + now)
    link.symlink_to(destination)
    os.replace(link, "/opt/mail-guardian/current")
    sync_directory(Path("/opt/mail-guardian"))
    run(["/usr/bin/systemctl", "daemon-reload"])
    run(["/usr/bin/systemd-analyze", "verify", "/etc/systemd/system/mail-guardian@.service",
         "/etc/systemd/system/mail-guardian@.timer"])
    run(["/usr/sbin/visudo", "-c"])
    run(["/usr/bin/python3", str(destination / "check_host.py"), "--json"])
    installer.verify_package(destination)
    assert_stopped()
    assert_empty(config / "credentials")
    assert_empty(data, worker.pw_uid, gid)
    if Path("/opt/mail-guardian/current").readlink() != destination:
        raise RuntimeError("new release pointer failed verification")
    for unit in ("mail-guardian@.service", "mail-guardian@.timer"):
        if digest(Path("/etc/systemd/system") / unit) != digest(destination / unit):
            raise RuntimeError("new systemd unit failed verification")
    if digest(Path("/usr/local/libexec/mail-guardian-maintenance")) != digest(destination / "maintenance.py"):
        raise RuntimeError("new helper failed verification")
    record["complete"] = True
    atomic_bytes(archive / "receipt.json", json.dumps(record, indent=2).encode(), 0o600)
    (config / "migration-pending").unlink()
    sync_directory(config)
    print(json.dumps(record))

if __name__ == "__main__":
    main()
