#!/usr/bin/python3
"""Initial, offline provisioning. Updates and mailbox cutover are separate work."""

import argparse
import fcntl
import grp
import hashlib
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile

ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LANG": "C.UTF-8"}
UBUNTU_RELEASES = frozenset({"24.04", "26.04", "26.10"})


def validate_platform(os_release, machine):
    # Keep a release allowlist: a newer Ubuntu, derivative, or architecture is
    # not qualified merely because it can execute Python or the Go binary.
    if (os_release.get("ID") != "ubuntu" or
            os_release.get("VERSION_ID") not in UBUNTU_RELEASES or
            machine != "x86_64"):
        raise ValueError("initial deployment target is Ubuntu 24.04, 26.04 or 26.10 on amd64")


def command(args):
    return subprocess.run(args, env=ENV, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30).stdout.decode().strip()


def reject_symlink(path):
    path = Path(path)
    for entry in reversed((path,) + tuple(path.parents)):
        if entry.is_symlink():
            raise ValueError("symlink in installation destination")
        if entry.exists():
            info = entry.stat()
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError("installation destination must be administrator-owned")


def directory(path, mode=0o755, gid=0):
    path = Path(path)
    reject_symlink(path)
    path.mkdir(mode=mode, parents=True, exist_ok=True)
    if not path.is_dir():
        raise ValueError("installation destination is not a directory")
    os.chown(path, 0, gid)
    os.chmod(path, mode)
    return path


def atomic_file(source, target, mode=0o644, gid=0):
    target = Path(target)
    reject_symlink(target)
    fd, temporary = tempfile.mkstemp(prefix=".guardian-", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(Path(source).read_bytes())
            out.flush()
            os.fsync(out.fileno())
            os.fchown(out.fileno(), 0, gid)
            os.fchmod(out.fileno(), mode)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def install_migration_lock(parent, gid, held):
    """Publish an already-exclusively-locked stable inode; never replace it."""
    path = Path(parent) / "migration.lock"
    reject_symlink(path)
    if path.exists():
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != gid or
                info.st_mode & 0o7777 != 0o640 or info.st_nlink != 1):
            raise ValueError("existing migration fence has unsafe ownership or permissions")
        return
    fd, temporary = tempfile.mkstemp(prefix=".migration-lock-", dir=parent)
    lock = os.fdopen(fd, "r+b")
    held.append(lock)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.fchown(lock.fileno(), 0, gid)
        os.fchmod(lock.fileno(), 0o640)
        os.fsync(lock.fileno())
        # A hard-link publication is atomic and refuses an existing target.
        # Remove the temporary name before allowing worker metadata checks.
        os.link(temporary, path, follow_symlinks=False)
    finally:
        os.unlink(temporary)
    directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def verify_package(root):
    manifest = root / "SHA256SUMS"
    entries = set()
    for line in manifest.read_text().splitlines():
        digest, name = line.split("  ", 1)
        relative = Path(name)
        if not re.fullmatch(r"[0-9a-f]{64}", digest) or relative.is_absolute() or ".." in relative.parts or name in entries:
            raise ValueError("invalid package manifest")
        entries.add(name)
        file = root / relative
        if file.is_symlink() or not file.is_file() or hashlib.sha256(file.read_bytes()).hexdigest() != digest:
            raise ValueError("package checksum mismatch")
    actual = {str(file.relative_to(root)) for file in root.rglob("*") if file.is_file() and file != manifest}
    if entries != actual or any(file.is_symlink() for file in root.rglob("*")):
        raise ValueError("package contains unlisted files or symlinks")
    return entries


def active(unit):
    result = subprocess.run(["/usr/bin/systemctl", "is-active", "--quiet", unit], env=ENV, timeout=15)
    return result.returncode == 0


def enabled(unit):
    result = subprocess.run(["/usr/bin/systemctl", "is-enabled", "--quiet", unit], env=ENV, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
    return result.returncode == 0


def install(args):
    if os.geteuid() != 0:
        raise ValueError("run initial installation as root")
    # Serialize fresh installs too, before an instance directory or its own
    # fence exists. Never unlink the lock inode while installers can run. This
    # root-only runtime lock file may be created by the read-only --check.
    reject_symlink("/run")
    fd = os.open("/run/mail-guardian-provision.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "r+b") as lock:
        info = os.fstat(lock.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077 or info.st_nlink != 1:
            raise ValueError("unsafe global provisioning lock")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("another provisioning operation is running") from None
        return install_locked(args)


def install_locked(args):
    # A previously provisioned instance has one stable fence inode. The
    # installer holds it exclusively while checking or changing that instance,
    # preventing manual workers and the helper from racing provisioning. A
    # fresh install has no directory or worker yet; old installations without
    # a fence require an explicit, stopped upgrade path rather than guessing.
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,28}", args.instance):
        raise ValueError("instance must have 1–29 lowercase letters, digits or hyphens")
    if os.geteuid() != 0:
        raise ValueError("run initial installation as root")
    root = Path("/etc/mail-guardian") / args.instance
    if not os.path.lexists(root):
        held = []
        try:
            return _install(args, held)
        finally:
            for lock in held:
                lock.close()
    reject_symlink(root)
    if not root.is_dir():
        raise ValueError("existing instance path is not a directory")
    try:
        account = pwd.getpwnam("mg-" + args.instance)
    except KeyError:
        raise ValueError("existing instance has no worker account") from None
    path = root / "migration.lock"
    reject_symlink(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as lock:
        info = os.fstat(lock.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != account.pw_gid or
                info.st_mode & 0o7777 != 0o640 or info.st_nlink != 1):
            raise ValueError("existing migration fence has unsafe ownership or permissions")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("instance is in use or migration is in progress") from None
        return _install(args, [])


def _install(args, held):
    instance = args.instance
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,28}", instance):
        raise ValueError("instance must have 1–29 lowercase letters, digits or hyphens")
    if os.geteuid() != 0:
        raise ValueError("run initial installation as root")
    os.umask(0o022)
    release = Path(__file__).resolve().parent
    verify_package(release)
    version = (release / "VERSION").read_text().strip()
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[.-][A-Za-z0-9]+)*", version):
        raise ValueError("invalid release version")
    os_release = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        key, _, value = line.partition("=")
        os_release[key] = value.strip('"')
    validate_platform(os_release, platform.machine())
    systemd = command(["/usr/bin/systemctl", "--version"]).splitlines()[0]
    if int(systemd.split()[1]) < 249:
        raise ValueError("systemd with LoadCredential support is required")
    command(["/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "compose", "version"])
    command(["/usr/sbin/visudo", "-c"])
    marker = Path("/etc/mail-guardian/instance")
    reject_symlink(marker)
    if marker.exists() and marker.read_text().strip() != instance:
        raise ValueError("this initial package permits only one instance per host")
    pending = Path("/etc/mail-guardian") / instance / "migration-pending"
    if os.path.lexists(pending):
        raise ValueError("migration requires administrator recovery before provisioning")
    current = Path("/opt/mail-guardian/current")
    destination = Path("/opt/mail-guardian/releases") / version
    reject_symlink(destination)
    if current.exists() or current.is_symlink():
        info = current.lstat()
        if not current.is_symlink() or info.st_uid != 0 or current.readlink() != destination:
            raise ValueError("a different release is installed; a checked update procedure is required")
    if active("mail-guardian@" + instance + ".service") or active("mail-guardian@" + instance + ".timer") or enabled("mail-guardian@" + instance + ".timer"):
        raise ValueError("stop the worker and stop/disable the timer before rerunning initial provisioning")
    if args.config:
        source = Path(args.config)
        reject_symlink(source)
        command([str(release / "guardian"), "--config", str(source), "server", "validate-config", "--instance", instance])
        existing_config = Path("/etc/mail-guardian") / instance / "config.toml"
        reject_symlink(existing_config)
        if existing_config.exists() and existing_config.read_bytes() != source.read_bytes():
            raise ValueError("existing configuration will not be overwritten")
    if args.check:
        print("Host and package checks passed; nothing installed or started. A root-only provisioning lock may have been created in /run.")
        return
    user = "mg-" + instance
    try:
        account = pwd.getpwnam(user)
        if (account.pw_uid == 0 or account.pw_shell not in ("/usr/sbin/nologin", "/sbin/nologin") or
                account.pw_dir != "/var/lib/mail-guardian/" + instance or grp.getgrgid(account.pw_gid).gr_name != user):
            raise ValueError("existing worker account is unsuitable")
    except KeyError:
        command(["/usr/sbin/useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/var/lib/mail-guardian/" + instance,
                 "--shell", "/usr/sbin/nologin", user])
        account = pwd.getpwnam(user)
    if any(group.gr_gid != account.pw_gid and user in group.gr_mem for group in grp.getgrall()):
        raise ValueError("worker must have only its dedicated group")
    directory("/etc/mail-guardian")
    directory("/var/lib/mail-guardian")
    config_root = directory("/etc/mail-guardian/" + instance, 0o750, account.pw_gid)
    install_migration_lock(config_root, account.pw_gid, held)
    directory(config_root / "credentials", 0o700)
    data = Path("/var/lib/mail-guardian") / instance
    # Parent is administrator-owned. Never traverse worker-owned entries as root.
    if data.is_symlink():
        raise ValueError("worker state directory must not be a symlink")
    if not data.exists():
        data.mkdir(mode=0o700)
        os.chown(data, account.pw_uid, account.pw_gid)
    elif not data.is_dir() or data.stat().st_uid != account.pw_uid or data.stat().st_mode & 0o077:
        raise ValueError("existing worker state has unsafe owner or permissions")
    directory("/opt/mail-guardian")
    directory("/opt/mail-guardian/releases")
    if destination.exists():
        if verify_package(destination) != verify_package(release) or (destination / "SHA256SUMS").read_bytes() != (release / "SHA256SUMS").read_bytes():
            raise ValueError("installed release differs from this package")
    else:
        temporary = Path(tempfile.mkdtemp(prefix=".guardian-", dir=destination.parent))
        try:
            shutil.copytree(release, temporary, dirs_exist_ok=True)
            for path in temporary.rglob("*"):
                os.chown(path, 0, 0)
                os.chmod(path, 0o755 if path.is_dir() or path.name in ("guardian", "maintenance.py", "install.sh", "install.py") else 0o644)
            os.chmod(temporary, 0o755)
            os.rename(temporary, destination)
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)
    directory("/usr/local/libexec")
    atomic_file(destination / "maintenance.py", "/usr/local/libexec/mail-guardian-maintenance", 0o755)
    deploy = config_root / "deploy"
    if deploy.exists():
        # Initial provisioning does not overwrite locally reviewed admin config.
        reject_symlink(deploy)
        for entry in deploy.rglob("*"):
            reject_symlink(entry)
    else:
        shutil.copytree(destination / "deploy", deploy)
    config = config_root / "config.toml"
    if args.config:
        reject_symlink(config)
        if config.exists() and config.read_bytes() != Path(args.config).read_bytes():
            raise ValueError("existing configuration will not be overwritten")
        atomic_file(args.config, config, 0o640, account.pw_gid)
    for name in ("mail-guardian@.service", "mail-guardian@.timer"):
        atomic_file(destination / name, "/etc/systemd/system/" + name)
    directory("/var/lib/mail-guardian-admin", 0o700)
    # The generated controller bind-file must survive Docker's boot-time
    # restart. It is administrator state, separate from the worker and locks.
    tmpfiles = "d /var/lib/mail-guardian-admin 0700 root root -\n"
    sudoers = ("Defaults:" + user + " env_reset\n" + user + " ALL=(root) NOPASSWD: " +
               ", ".join("/usr/local/libexec/mail-guardian-maintenance " + instance + " " + op
                          for op in ("up", "down", "status", "deep-check", "check-storage", "check-persistence", "export-redis")) + "\n")
    with tempfile.TemporaryDirectory() as scratch:
        temp = Path(scratch) / "sudoers"
        temp.write_text(sudoers)
        temp.chmod(0o440)
        command(["/usr/sbin/visudo", "-cf", str(temp)])
        atomic_file(temp, "/etc/sudoers.d/mail-guardian", 0o440)
        temp.write_text(tmpfiles)
        atomic_file(temp, "/etc/tmpfiles.d/mail-guardian.conf")
        temp.write_text(instance + "\n")
        atomic_file(temp, marker)
    if not current.exists():
        current.symlink_to(destination)
    command(["/usr/bin/systemctl", "daemon-reload"])
    # Deliberately no enable/start: protect mode can mutate real mailbox state.
    print("Installed Mail Guardian " + version + " for " + instance + ". Scheduling remains OFF.")
    print("Provision the three root-owned credentials securely, then complete pilot and recovery acceptance before starting the timer.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--instance", required=True)
    parser.add_argument("--config")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        install(args)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print("Installation stopped: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
