#!/usr/bin/env python3
"""Rehearse the Redis RDB-to-AOF conversion using synthetic data only.

This is a disposable integration test, NOT a production restore command. It
creates two uniquely named volumes and containers with no network, no exposed
ports and no connection to any existing Guardian data. It has no input option
for an existing RDB or volume. Docker access is privileged: review before use.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import uuid

IMAGE = "redis:7.4.9-alpine@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99"
LABEL = "org.mailguardian.redis-rehearsal"
SOCKET = "unix:///var/run/docker.sock"
CONFIG = Path(__file__).resolve().parents[1] / "deploy/redis/redis.conf"


def run(args, *, input_file=None, output_file=None, timeout=45):
    p = subprocess.run(["docker", "--host", SOCKET, *args], stdin=input_file,
                       stdout=output_file or subprocess.PIPE, stderr=subprocess.PIPE,
                       timeout=timeout, check=False)
    if p.returncode:
        raise RuntimeError("Docker command failed: " + " ".join(args[:3]) + ": " +
                           p.stderr.decode("utf-8", "replace")[:1000])
    return b"" if output_file else p.stdout


def redis(container, *args):
    return run(["exec", container, "redis-cli", "--raw", *args]).decode("utf-8").strip()


def persistence_ok(text):
    fields = dict(line.split(":", 1) for line in text.splitlines() if ":" in line and not line.startswith("#"))
    return all(fields.get(key) == expected for key, expected in {
        "aof_enabled": "1", "aof_rewrite_in_progress": "0",
        "aof_rewrite_scheduled": "0", "aof_last_bgrewrite_status": "ok",
        "aof_last_write_status": "ok", "rdb_last_bgsave_status": "ok",
    }.items())


def await_aof(container):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if persistence_ok(redis(container, "INFO", "persistence")):
            if redis(container, "CONFIG", "GET", "appendfsync") != "appendfsync\nalways":
                raise RuntimeError("appendfsync is not always")
            return
        time.sleep(0.2)
    raise RuntimeError("AOF persistence did not become healthy")


def assert_data(container):
    # Explicit type/value checks over two databases; no expiry assumptions.
    cases = [
        (("DBSIZE",), "3"),
        (("TYPE", "guardian:sample"), "string"),
        (("GET", "guardian:sample"), "synthetic sample"),
        (("TYPE", "guardian:model"), "hash"),
        (("HMGET", "guardian:model", "spam", "ham"), "19\n23"),
        (("TYPE", "guardian:tokens"), "zset"),
        (("ZRANGE", "guardian:tokens", "0", "-1", "WITHSCORES"), "alpha\n1\nbeta\n2"),
        (("-n", "2", "DBSIZE"), "1"),
        (("-n", "2", "GET", "other-db"), "synthetic second database"),
    ]
    for command, expected in cases:
        if redis(container, *command) != expected:
            raise RuntimeError("synthetic data did not survive: " + " ".join(command))


def label_value(kind, name):
    args = ["inspect", "--format", "{{json .Config.Labels}}", name] if kind == "container" else ["volume", "inspect", "--format", "{{json .Labels}}", name]
    labels = json.loads(run(args).decode())
    return labels.get(LABEL) if isinstance(labels, dict) else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", required=True, help="run the synthetic Docker integration test")
    parser.parse_args()
    if not CONFIG.is_file():
        raise RuntimeError("repository Redis configuration not found")
    token = uuid.uuid4().hex
    names = ["mg-redis-rehearsal-" + token + "-source", "mg-redis-rehearsal-" + token + "-target"]
    volumes, containers = [], []
    try:
        # Pulling is intentionally excluded: require the pinned image already
        # available, so Docker cannot silently substitute a different tag.
        run(["image", "inspect", IMAGE])
        for name in names:
            result = subprocess.run(["docker", "--host", SOCKET, "volume", "inspect", name],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
            if result.returncode == 0:
                raise RuntimeError("generated volume name already exists")
            run(["volume", "create", "--label", LABEL + "=" + token, name])
            volumes.append(name)
            if label_value("volume", name) != token:
                raise RuntimeError("volume ownership label does not match")
            # Do not reuse a dirty volume, even on a coincidental name match.
            run(["run", "--rm", "--network", "none", "--mount", "type=volume,src=" + name + ",dst=/data,readonly",
                 "--entrypoint", "sh", IMAGE, "-c", 'test -z "$(ls -A /data)"'])

        def create(name, volume, aof_override):
            args = ["create", "--name", name, "--label", LABEL + "=" + token,
                    "--network", "none", "--user", "redis", "--read-only",
                    "--security-opt", "no-new-privileges:true", "--cap-drop", "ALL",
                    "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
                    "--mount", "type=volume,src=" + volume + ",dst=/data",
                    "--mount", "type=bind,src=" + str(CONFIG) + ",dst=/guardian-redis.conf,readonly",
                    IMAGE, "redis-server", "/guardian-redis.conf"]
            if aof_override:
                args += ["--appendonly", "no"]
            cid = run(args).decode().strip()
            containers.append(cid)
            if label_value("container", cid) != token:
                raise RuntimeError("container ownership label does not match")
            return cid

        def start(cid):
            run(["start", cid])
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                try:
                    if redis(cid, "PING") == "PONG":
                        return
                except RuntimeError:
                    pass
                time.sleep(0.2)
            logs = run(["logs", "--tail", "30", cid]).decode("utf-8", "replace")
            raise RuntimeError("Redis failed to start: " + logs[-2000:])

        source = create(names[0], names[0], True)
        start(source)
        for args in [("SET", "guardian:sample", "synthetic sample"),
                     ("HSET", "guardian:model", "spam", "19", "ham", "23"),
                     ("ZADD", "guardian:tokens", "1", "alpha", "2", "beta"),
                     ("-n", "2", "SET", "other-db", "synthetic second database")]:
            redis(source, *args)
        assert_data(source)
        if redis(source, "SAVE") != "OK":
            raise RuntimeError("synthetic RDB save failed")
        run(["exec", source, "redis-check-rdb", "/data/dump.rdb"])
        source_digest = run(["exec", source, "sha256sum", "/data/dump.rdb"]).decode().split()[0]

        target = create(names[1], names[1], True)
        # Docker's tar stream moves only our newly created synthetic RDB.
        with tempfile.TemporaryFile() as archive:
            run(["cp", source + ":/data/dump.rdb", "-"], output_file=archive)
            if archive.tell() > (1 << 20):
                raise RuntimeError("synthetic RDB tar unexpectedly large")
            archive.seek(0)
            run(["cp", "-", target + ":/data/"], input_file=archive)
        start(target)
        run(["exec", target, "redis-check-rdb", "/data/dump.rdb"])
        target_digest = run(["exec", target, "sha256sum", "/data/dump.rdb"]).decode().split()[0]
        if source_digest != target_digest:
            raise RuntimeError("synthetic RDB changed during transfer")
        assert_data(target)
        if redis(target, "CONFIG", "SET", "appendonly", "yes") != "OK":
            raise RuntimeError("could not enable AOF")
        await_aof(target)
        run(["stop", "--time", "15", target], timeout=25)
        # Normal production config enables AOF. Restart in a new container on
        # the same disposable target volume; a successful bootstrap is not
        # enough unless the values survive this restart.
        final = create(names[1] + "-normal", names[1], False)
        start(final)
        await_aof(final)
        assert_data(final)
        print("PASS: synthetic RDB loaded, AOF rewrite completed, and all sample data survived normal-config restart")
        print("LIMIT: synthetic data only; real model, full-state migration and recovery remain unverified")
    finally:
        cleanup_errors = []
        for cid in reversed(containers):
            try:
                if label_value("container", cid) == token:
                    run(["rm", "-f", cid], timeout=30)
                else:
                    cleanup_errors.append("container ownership label changed: " + cid)
            except Exception as error:
                cleanup_errors.append("container " + cid + ": " + type(error).__name__)
        for name in reversed(volumes):
            try:
                if label_value("volume", name) == token:
                    run(["volume", "rm", name])
                else:
                    cleanup_errors.append("volume ownership label changed: " + name)
            except Exception as error:
                cleanup_errors.append("volume " + name + ": " + type(error).__name__)
        if cleanup_errors:
            raise RuntimeError("test resource cleanup requires attention: " + "; ".join(cleanup_errors))


if __name__ == "__main__":
    main()
