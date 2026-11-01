#!/usr/bin/env python3
"""Import a verified RDB into the new, fixed Guardian pilot Redis volume.

The coordinator must first stop/disable Guardian and publish migration-pending
under the instance fence. This command holds that exclusive fence, refuses an
existing production volume, and leaves the marker in place. It never reads
mailbox credentials or publishes the database/configuration. Failed imports
retain their labelled volumes for explicit operator recovery.
"""

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import uuid

IMAGE = "redis:7.4.9-alpine@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99"
LABEL = "org.mailguardian.model-import"
INSTANCE_ROOT = Path("/etc/mail-guardian/pilot")
CURRENT = Path("/opt/mail-guardian/current")
RELEASES = Path("/opt/mail-guardian/releases")
PROJECT = "mail-guardian-pilot"
TARGET = PROJECT + "_redis_data"
ENVIRONMENT = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LANG": "C.UTF-8"}


def run(args, timeout=120):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, check=False, env=ENVIRONMENT)
    if result.returncode:
        raise RuntimeError("model import dependency failed")
    return result.stdout


def docker(*args):
    return run(["/usr/bin/docker", "--host", "unix:///var/run/docker.sock", *args])


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def trusted(path, *, directory=False, private=False, owner=0):
    path = Path(path)
    if not path.is_absolute() or str(path) != os.path.normpath(path):
        raise ValueError("administrator path must be absolute and normalized")
    for entry in reversed((path,) + tuple(path.parents)):
        info = entry.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
            raise ValueError("unsafe administrator path")
        if entry != path and not stat.S_ISDIR(info.st_mode):
            raise ValueError("unsafe administrator parent")
    info = path.lstat()
    expected = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not expected or (not directory and info.st_nlink != 1):
        raise ValueError("unsafe administrator object type or links")
    if private and info.st_mode & 0o077:
        raise ValueError("administrator file or directory must be private")
    return info


@contextlib.contextmanager
def exclusive_fence():
    root = trusted(INSTANCE_ROOT, directory=True)
    lock = INSTANCE_ROOT / "migration.lock"
    before = trusted(lock)
    if (stat.S_IMODE(root.st_mode) != 0o750 or stat.S_IMODE(before.st_mode) != 0o640 or
            before.st_gid != root.st_gid):
        raise ValueError("unsafe instance fence")
    fd = os.open(lock, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("instance fence changed")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        trusted(INSTANCE_ROOT / "migration-pending", private=True)
        yield
    finally:
        os.close(fd)


def verified_release(expected):
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("expected release manifest digest is required")
    link = CURRENT.lstat()
    if link.st_uid != 0 or not stat.S_ISLNK(link.st_mode):
        raise ValueError("current release pointer is unsafe")
    release = CURRENT.resolve(strict=True)
    if release.parent != RELEASES:
        raise ValueError("unexpected installed release location")
    trusted(release, directory=True)
    manifest = release / "SHA256SUMS"
    trusted(manifest)
    if digest(manifest) != expected:
        raise ValueError("installed release manifest mismatch")
    entries = set()
    for line in manifest.read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if match is None:
            raise ValueError("invalid installed release manifest")
        wanted, name = match.groups()
        relative = Path(name)
        if (relative.is_absolute() or ".." in relative.parts or
                str(relative) != name or name in entries):
            raise ValueError("unsafe installed manifest entry")
        payload = release / name
        trusted(payload)
        if digest(payload) != wanted:
            raise ValueError("installed release payload mismatch")
        entries.add(name)
    if not {"guardian-recovery", "deploy/redis/redis.conf", "deploy/compose.yaml"} <= entries:
        raise ValueError("release lacks required model import components")
    for relative in ("redis/redis.conf", "compose.yaml"):
        actual = INSTANCE_ROOT / "deploy" / relative
        trusted(actual)
        if digest(actual) != digest(release / "deploy" / relative):
            raise ValueError("installed Compose or Redis config differs from reviewed release")
    compose = (release / "deploy/compose.yaml").read_text()
    if IMAGE not in compose or "- redis_data:/data" not in compose or "container_name:" in compose:
        raise ValueError("release has an unexpected Redis volume contract")
    return release


def require_quiescent():
    for unit in ("mail-guardian@pilot.service", "mail-guardian@pilot.timer"):
        state = run(["/usr/bin/systemctl", "show", "--property=ActiveState", "--value", unit]).decode().strip()
        if state != "inactive":
            raise ValueError("Guardian worker and timer must be inactive")
    enabled = run(["/usr/bin/systemctl", "show", "--property=UnitFileState", "--value",
                   "mail-guardian@pilot.timer"]).decode().strip()
    if enabled != "disabled":
        raise ValueError("Guardian timer must be disabled")
    if docker("ps", "--all", "--filter", "label=com.docker.compose.project=" + PROJECT,
              "--format", "{{.ID}}").strip():
        raise ValueError("Guardian Compose containers must be absent during first import")
    if TARGET in docker("volume", "ls", "--format", "{{.Name}}").decode().splitlines():
        raise ValueError("target model volume already exists; import will not overwrite it")


def redis(name, *args):
    return docker("exec", name, "redis-cli", "--raw", *args).decode().strip()


def persistence_ready(name):
    fields = dict(line.split(":", 1) for line in redis(name, "INFO", "persistence").splitlines()
                  if ":" in line and not line.startswith("#"))
    expected = {"aof_enabled": "1", "aof_rewrite_in_progress": "0",
                "aof_rewrite_scheduled": "0", "aof_last_bgrewrite_status": "ok",
                "aof_last_write_status": "ok", "rdb_last_bgsave_status": "ok"}
    return (all(fields.get(k) == v for k, v in expected.items()) and
            redis(name, "CONFIG", "GET", "appendfsync") == "appendfsync\nalways")


def wait_for(check):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            if check():
                return
        except RuntimeError:
            pass
        time.sleep(0.2)
    raise RuntimeError("model import readiness deadline exceeded")


def import_model(rdb, expected, release, manifest_digest, report_path):
    token = uuid.uuid4().hex
    reference_volume = "mg-import-" + token + "-reference"
    names = ["mg-import-" + token + "-reference", "mg-import-" + token + "-target"]
    volumes, containers, comparisons = [], [], []
    success = False
    report = {"source_sha256": expected, "release_manifest_sha256": manifest_digest,
              "image": IMAGE, "token": token, "target_volume": TARGET,
              "mailbox_access": False, "migration_pending_preserved": True,
              "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    try:
        docker("image", "inspect", IMAGE)
        for volume in (reference_volume, TARGET):
            labels = ["--label", LABEL + "=" + token]
            if volume == TARGET:
                labels += ["--label", "com.docker.compose.project=" + PROJECT,
                           "--label", "com.docker.compose.volume=redis_data"]
            docker("volume", "create", *labels, volume)
            actual = json.loads(docker("volume", "inspect", "--format", "{{json .Labels}}", volume))
            if actual.get(LABEL) != token:
                raise RuntimeError("model volume ownership did not verify")
            volumes.append(volume)
            docker("run", "--rm", "--network", "none", "--user", "0",
                   "--read-only", "--cap-drop", "ALL", "--cap-add", "CHOWN",
                   "--security-opt", "no-new-privileges:true",
                   "--mount", "type=bind,src=" + str(rdb) + ",dst=/source.rdb,readonly",
                   "--mount", "type=volume,src=" + volume + ",dst=/data",
                   "--entrypoint", "sh", IMAGE, "-ec",
                   'test -z "$(ls -A /data)"; chown 0:0 /data; cp /source.rdb /data/dump.rdb; '
                   'redis-check-rdb /data/dump.rdb; chown redis:redis /data /data/dump.rdb')

        def create(name, volume, normal=False):
            command = ["create", "--name", name, "--label", LABEL + "=" + token,
                       "--user", "redis", "--read-only", "--cap-drop", "ALL",
                       "--security-opt", "no-new-privileges:true", "--memory", "256m",
                       "--pids-limit", "96", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
                       "--publish", "127.0.0.1::6379",
                       "--mount", "type=volume,src=" + volume + ",dst=/data",
                       "--mount", "type=bind,src=" + str(INSTANCE_ROOT / "deploy/redis/redis.conf") +
                       ",dst=/usr/local/etc/redis/redis.conf,readonly",
                       IMAGE, "redis-server", "/usr/local/etc/redis/redis.conf"]
            if not normal:
                command += ["--appendonly", "no", "--save", ""]
            docker(*command)
            containers.append(name)
            docker("start", name)
            wait_for(lambda: redis(name, "PING") == "PONG")

        def endpoint(name):
            ports = json.loads(docker("inspect", "--format", "{{json .NetworkSettings.Ports}}", name))
            binding, = ports["6379/tcp"]
            if binding["HostIp"] != "127.0.0.1":
                raise RuntimeError("import endpoint is not restricted to loopback")
            return "127.0.0.1:" + binding["HostPort"]

        def compare():
            result = json.loads(run([str(release / "guardian-recovery"), "compare-redis",
                                     "--a", endpoint(names[0]), "--b", endpoint(names[1]),
                                     "--verified-no-additional-state"]))
            if result.get("equivalent") is not True:
                raise RuntimeError("restored model equivalence was not established")
            comparisons.append(result)

        create(names[0], reference_volume)
        create(names[1], TARGET)
        compare()
        if redis(names[1], "CONFIG", "SET", "appendonly", "yes") != "OK":
            raise RuntimeError("model AOF conversion was not accepted")
        wait_for(lambda: persistence_ready(names[1]))
        compare()
        docker("stop", "--time", "30", names[1])
        docker("rm", names[1])
        containers.remove(names[1])
        create(names[1], TARGET, normal=True)
        wait_for(lambda: persistence_ready(names[1]))
        compare()
        if digest(rdb) != expected:
            raise RuntimeError("source model changed during import")
        report.update({"success": True, "comparisons": comparisons,
                       "normal_config_aof_restart": True,
                       "completed_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
        success = True
    finally:
        cleanup_errors = 0
        for name in containers:
            try:
                labels = json.loads(docker("inspect", "--format", "{{json .Config.Labels}}", name))
                if labels.get(LABEL) != token:
                    raise RuntimeError("import container ownership changed")
                docker("stop", "--time", "30", name)
                docker("rm", name)
            except (RuntimeError, OSError, subprocess.SubprocessError, ValueError, TypeError):
                cleanup_errors += 1
        removed = []
        if success and not cleanup_errors and reference_volume in volumes:
            try:
                labels = json.loads(docker("volume", "inspect", "--format", "{{json .Labels}}", reference_volume))
                if labels.get(LABEL) != token:
                    raise RuntimeError("reference model volume ownership changed")
                docker("volume", "rm", reference_volume)
                removed.append(reference_volume)
            except (RuntimeError, OSError, subprocess.SubprocessError, ValueError, TypeError):
                cleanup_errors += 1
        report.update({"cleanup_complete": not cleanup_errors, "cleanup_errors": cleanup_errors,
                       "retained_volumes": [name for name in volumes if name not in removed]})
        if not success:
            report.update({"success": False, "comparisons_completed": len(comparisons)})
        with report_path.open("x") as stream:
            json.dump(report, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
    if cleanup_errors:
        raise RuntimeError("model imported but temporary resource cleanup needs inspection")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rdb", required=True, type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--release-manifest-sha256", required=True)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    if os.geteuid() != 0 or not re.fullmatch(r"[0-9a-f]{64}", args.sha256):
        raise ValueError("root and the verified source digest are required")
    info = trusted(args.rdb, private=True)
    if not 10 <= info.st_size <= 128 << 20 or digest(args.rdb) != args.sha256:
        raise ValueError("source model size or digest mismatch")
    trusted(args.report.parent, directory=True, private=True)
    if args.report.exists() or args.report.is_symlink():
        raise ValueError("model import report already exists")
    with exclusive_fence():
        release = verified_release(args.release_manifest_sha256)
        require_quiescent()
        report = import_model(args.rdb, args.sha256, release, args.release_manifest_sha256, args.report)
        trusted(INSTANCE_ROOT / "migration-pending", private=True)
    print(json.dumps({"success": True, "target_volume": TARGET,
                      "model_sha256": args.sha256, "comparisons": len(report["comparisons"]),
                      "migration_pending_preserved": True, "report": str(args.report)}))


if __name__ == "__main__":
    main()
