#!/usr/bin/python3
"""Read-only application evidence, always opened and closed as mg-pilot."""
import contextlib
import json
import os
from pathlib import Path
import pwd
import sqlite3
import stat
import sys

DATA = Path("/var/lib/mail-guardian/pilot")
FINAL = ("kept", "observed", "quarantined", "rescued", "review", "purged", "restored", "superseded")


def private_file(path, owner):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_nlink != 1 or
            stat.S_IMODE(info.st_mode) & 0o077):
        raise ValueError("unsafe worker evidence path")
    return info


def snapshot(data=DATA, owner=None):
    owner = os.geteuid() if owner is None else owner
    database, heartbeat = data / "guardian.db", data / "service-health.json"
    before = private_file(database, owner)
    private_file(heartbeat, owner)
    raw = heartbeat.read_bytes()
    if len(raw) > 32768:
        raise ValueError("heartbeat exceeds limit")
    beat = json.loads(raw)
    # WAL/SHM bookkeeping, including connection close, stays in the instance
    # user's scope. A SQLite context manager alone does not close a connection.
    with contextlib.closing(sqlite3.connect("file:" + str(database) + "?mode=ro", uri=True,
                                          timeout=5)) as db:
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA trusted_schema=OFF")
        db.execute("BEGIN")
        columns = "id,started_at,finished_at,command,dry_run,status,errors,purged"
        actual = db.execute("SELECT " + columns + " FROM runs WHERE dry_run=0 ORDER BY id DESC LIMIT 1").fetchone()
        latest = db.execute("SELECT id FROM runs ORDER BY id DESC LIMIT 1").fetchone()
        if actual is None or latest is None:
            raise ValueError("actual worker run missing")
        result = {"actual": dict(zip(columns.split(","), actual)), "latest_id": latest[0],
                  "open_runs": db.execute("SELECT count(*) FROM runs WHERE status='running' OR finished_at IS NULL OR finished_at=''").fetchone()[0],
                  "pending_messages": db.execute("SELECT count(*) FROM messages WHERE status IS NULL OR status NOT IN (" +
                                                 ",".join("?" for _ in FINAL) + ")", FINAL).fetchone()[0],
                  "reconciliations": db.execute("SELECT count(*) FROM reconciliations").fetchone()[0],
                  "model_checkpoint": any(value for key,value in db.execute("SELECT key,value FROM settings WHERE key IN ('model_checkpoint_required','bayes_rollback_at')")),
                  "heartbeat": beat}
    if not os.path.samestat(before, private_file(database, owner)) or raw != heartbeat.read_bytes():
        raise ValueError("worker evidence changed during observation")
    return result


def main():
    try:
        if pwd.getpwuid(os.geteuid()).pw_name != "mg-pilot":
            raise ValueError("dedicated worker user required")
        result = snapshot()
    except Exception:
        print("worker application evidence unavailable", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
