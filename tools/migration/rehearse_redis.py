#!/usr/bin/env python3
"""Restore one private Guardian model into isolated disposable Redis volumes.

Run on the Linux VPS as root. No mailbox credentials, production volume or
Rspamd are used. The input RDB is never changed. Both Redis endpoints bind only
to IPv4 loopback and are removed at the end. Failures retain labelled volumes
for investigation; successful rehearsals remove only their own volumes.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time
import uuid

IMAGE = "redis:7.4.9-alpine@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99"
LABEL = "org.mailguardian.real-model-rehearsal"


def run(args, timeout=90):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, check=False)
    if result.returncode:
        # Docker diagnostics may include data; retain them only in the private
        # operator environment, never include them in exceptions or JSON.
        raise RuntimeError("model rehearsal dependency failed: " + args[0])
    return result.stdout


def docker(*args, timeout=90):
    return run(["/usr/bin/docker", "--host", "unix:///var/run/docker.sock", *args], timeout)


def redis(name, *args):
    return docker("exec", name, "redis-cli", "--raw", *args).decode().strip()


def persistence_ready(name):
    fields = dict(line.split(":", 1) for line in redis(name, "INFO", "persistence").splitlines()
                  if ":" in line and not line.startswith("#"))
    return all(fields.get(k) == v for k, v in {
        "aof_enabled": "1", "aof_rewrite_in_progress": "0",
        "aof_rewrite_scheduled": "0", "aof_last_bgrewrite_status": "ok",
        "aof_last_write_status": "ok", "rdb_last_bgsave_status": "ok",
    }.items())


def wait_for(check, seconds=45):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if check():
                return
        except RuntimeError:
            pass
        time.sleep(0.2)
    raise RuntimeError("model rehearsal readiness deadline exceeded")


def private_file(path):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            info.st_mode & 0o077 or info.st_uid != os.geteuid()):
        raise ValueError("input must be a private owned regular file")
    if not 10 <= info.st_size <= 128 << 20:
        raise ValueError("model size outside supported bounds")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rdb", required=True, type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--recovery", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    if os.geteuid() != 0 or not args.rdb.is_absolute() or args.rdb.is_symlink():
        raise ValueError("use root and an absolute private model path")
    private_file(args.rdb)
    if args.report.exists() or args.report.is_symlink():
        raise ValueError("report already exists")
    if hashlib.sha256(args.rdb.read_bytes()).hexdigest() != args.sha256:
        raise ValueError("source model digest mismatch")
    docker("image", "inspect", IMAGE)
    token = uuid.uuid4().hex
    names = ["mg-real-restore-" + token + "-reference", "mg-real-restore-" + token + "-target"]
    volumes, containers = [], []
    success = False
    comparisons = []
    report = {"source_sha256": args.sha256, "image": IMAGE, "token": token,
              "mailbox_access": False, "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    try:
        for name in names:
            docker("volume", "create", "--label", LABEL + "=" + token, name)
            labels = json.loads(docker("volume", "inspect", "--format", "{{json .Labels}}", name))
            if labels.get(LABEL) != token:
                raise RuntimeError("volume ownership did not verify")
            volumes.append(name)
            docker("run", "--rm", "--network", "none", "--user", "0",
                   "--read-only", "--cap-drop", "ALL", "--cap-add", "CHOWN",
                   "--security-opt", "no-new-privileges:true",
                   "--mount", "type=bind,src=" + str(args.rdb) + ",dst=/source.rdb,readonly",
                   "--mount", "type=volume,src=" + name + ",dst=/data",
                   "--entrypoint", "sh", IMAGE, "-ec",
                   # Docker initializes /data with the image's Redis owner.
                   # With only CHOWN, root must first own this empty disposable
                   # directory before it can create the private RDB inside it.
                   'test -z "$(ls -A /data)"; chown 0:0 /data; cp /source.rdb /data/dump.rdb; '
                   'redis-check-rdb /data/dump.rdb; chown redis:redis /data /data/dump.rdb')

        def create(name, volume, aof):
            docker("create", "--name", name, "--label", LABEL + "=" + token,
                   "--user", "redis", "--read-only", "--cap-drop", "ALL",
                   "--security-opt", "no-new-privileges:true", "--memory", "256m",
                   "--pids-limit", "96", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
                   "--publish", "127.0.0.1::6379",
                   "--mount", "type=volume,src=" + volume + ",dst=/data",
                   IMAGE, "redis-server", "--bind", "0.0.0.0", "--protected-mode", "no",
                   "--appendonly", "yes" if aof else "no", "--appendfsync", "always",
                   "--save", "", "--maxmemory", "128mb", "--maxmemory-policy", "noeviction")
            containers.append(name)
            docker("start", name)
            wait_for(lambda: redis(name, "PING") == "PONG")

        def endpoint(name):
            result = json.loads(docker("inspect", "--format", "{{json .NetworkSettings.Ports}}", name))
            binding, = result["6379/tcp"]
            if binding["HostIp"] != "127.0.0.1":
                raise RuntimeError("Redis is not restricted to loopback")
            return "127.0.0.1:" + binding["HostPort"]

        def compare():
            payload = run([str(args.recovery), "compare-redis", "--a", endpoint(names[0]),
                           "--b", endpoint(names[1]), "--verified-no-additional-state"])
            comparisons.append(json.loads(payload))

        for name in names:
            create(name, name, False)
        compare()
        if redis(names[1], "CONFIG", "SET", "appendonly", "yes") != "OK":
            raise RuntimeError("AOF conversion was not accepted")
        wait_for(lambda: persistence_ready(names[1]))
        compare()
        docker("stop", "--time", "30", names[1])
        docker("rm", names[1])
        containers.remove(names[1])
        create(names[1], names[1], True)
        wait_for(lambda: persistence_ready(names[1]))
        compare()
        if hashlib.sha256(args.rdb.read_bytes()).hexdigest() != args.sha256:
            raise RuntimeError("source model changed")
        report.update({"success": True, "comparisons": comparisons, "aof_restart": True,
                       "completed_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
        success = True
    finally:
        cleanup_errors = 0
        for name in containers:
            try:
                labels = json.loads(docker("inspect", "--format", "{{json .Config.Labels}}", name))
                if labels.get(LABEL) != token:
                    raise RuntimeError("container ownership changed during cleanup")
                docker("rm", "--force", name)
            except (RuntimeError, OSError, subprocess.SubprocessError, ValueError, TypeError):
                cleanup_errors += 1
        removed_volumes = []
        if success and not cleanup_errors:
            for name in volumes:
                try:
                    labels = json.loads(docker("volume", "inspect", "--format", "{{json .Labels}}", name))
                    if labels.get(LABEL) != token:
                        raise RuntimeError("volume ownership changed during cleanup")
                    docker("volume", "rm", name)
                    removed_volumes.append(name)
                except (RuntimeError, OSError, subprocess.SubprocessError, ValueError, TypeError):
                    cleanup_errors += 1
        report["cleanup_complete"] = not cleanup_errors
        report["cleanup_errors"] = cleanup_errors
        report["retained_volumes"] = [name for name in volumes if name not in removed_volumes]
        if not success:
            report.update({"success": False, "retained_volumes": volumes,
                           "comparisons_completed": len(comparisons)})
        with args.report.open("x") as stream:
            json.dump(report, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
    if cleanup_errors:
        raise RuntimeError("model comparison passed but disposable resource cleanup needs inspection")
    print(json.dumps({"success": True, "model_sha256": args.sha256,
                      "comparisons": len(comparisons), "report": str(args.report)}))


if __name__ == "__main__":
    main()
