#!/usr/bin/env python3
"""Read VPS-1 Guardian health over pinned SSH. Never starts a local worker."""

import datetime as dt
import importlib.util
import json
from pathlib import Path
import sys

LATEST_ACTUAL_QUERY = """SELECT id,started_at,finished_at,status,scanned,kept,rescued,
quarantined,review,learned_spam,learned_ham,purged,errors FROM runs
WHERE command='run' AND dry_run=0 AND finished_at IS NOT NULL AND finished_at<>''
ORDER BY id DESC LIMIT 1"""

WORKER_CONTEXT = r'''
@contextlib.contextmanager
def worker_identity():
    """Keep WAL/SHM creation and connection close under the worker identity."""
    account=pwd.getpwnam("mg-pilot")
    original_uid,original_gid,original_groups=os.geteuid(),os.getegid(),os.getgroups()
    try:
        os.setgroups([account.pw_gid])
        os.setegid(account.pw_gid)
        os.seteuid(account.pw_uid)
        yield
    finally:
        os.seteuid(original_uid)
        os.setegid(original_gid)
        os.setgroups(original_groups)
'''

REMOTE = r'''
import contextlib, datetime as dt, hashlib, json, os, pwd, re, sqlite3, stat, subprocess, tomllib
from pathlib import Path
ROOT=Path("/etc/mail-guardian/pilot")
STATE=Path("/var/lib/mail-guardian/pilot")
__WORKER_CONTEXT__

def read(path,limit):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,"rb") as f:
        st=os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_size>limit:
            raise ValueError("invalid status input")
        data=f.read(limit+1)
        if len(data)>limit:
            raise ValueError("status input exceeds bound")
        return data

def unit(name,fields):
    result=subprocess.run(["/usr/bin/systemctl","show",name,"--no-pager",*["--property="+x for x in fields]],
        check=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5)
    if len(result.stdout)>8192:
        raise ValueError("unit status exceeds bound")
    return dict(line.split("=",1) for line in result.stdout.decode().splitlines() if "=" in line)

def latest_backup():
    root=Path("/var/backups/mail-guardian/pilot")
    try:
        rows=list(root.iterdir())
    except FileNotFoundError:
        return None
    if len(rows)>10000:
        raise ValueError("backup catalog exceeds bound")
    for receipt in sorted(rows,reverse=True):
        if not re.fullmatch(r"[0-9]{8}T[0-9]{6}\.[0-9]{6}Z\.age\.sha256",receipt.name):
            continue
        name=receipt.name[:-7]
        raw=read(receipt,200).decode("ascii")
        info=(root/name).lstat()
        if re.fullmatch(r"[0-9a-f]{64}  "+re.escape(name)+r"\n",raw) and stat.S_ISREG(info.st_mode) and info.st_size>0:
            return {"name":name,"completed_utc":dt.datetime.strptime(name[:-4],"%Y%m%dT%H%M%S.%fZ").replace(tzinfo=dt.timezone.utc).isoformat()}
    return None

result={"protocol":1,"server":"VPS-1","observed_utc":dt.datetime.now(dt.timezone.utc).isoformat(),
        "service":unit("mail-guardian@pilot.service",["ActiveState","SubState","Result"]),
        "timer":unit("mail-guardian@pilot.timer",["ActiveState","SubState","UnitFileState","NextElapseUSecRealtime"]),
        "owner":"unconfirmed","policy":None,"latest_actual":None,"pending":0,"cursors":0,"open_runs":0,
        "model_recovery_required":False,"heartbeat":None,"backup":latest_backup()}
cfg=None
pending_migration=os.path.lexists(ROOT/"migration-pending")
if (ROOT/"config.toml").exists():
    cfg=tomllib.loads(read(ROOT/"config.toml",65536).decode())
    result["policy"]={"mode":cfg.get("safety",{}).get("mode"),"purge_enabled":cfg.get("safety",{}).get("purge_enabled")}
machine=read(Path("/etc/machine-id"),128).decode().strip()
# A read-only SQLite WAL connection may still create bookkeeping sidecars.
# Open, query AND close it as mg-pilot so these never become root-owned.
with worker_identity():
    database=STATE/"guardian.db"
    if cfg and database.exists():
        if not stat.S_ISREG(database.lstat().st_mode):
            raise ValueError("invalid status database")
        with contextlib.closing(sqlite3.connect("file:"+str(database)+"?mode=ro",uri=True,timeout=2)) as db:
            db.row_factory=sqlite3.Row
            db.execute("PRAGMA query_only=ON")
            db.execute("PRAGMA trusted_schema=OFF")
            db.execute("BEGIN")
            row=db.execute(__LATEST_QUERY__).fetchone()
            result["latest_actual"]=dict(row) if row else None
            result["pending"]=db.execute("SELECT count(*) FROM messages WHERE status IN ('pending_move','pending_learn','pending_restore','move_ambiguous','blocked','error')").fetchone()[0]
            result["cursors"]=db.execute("SELECT count(*) FROM reconciliations").fetchone()[0]
            result["open_runs"]=db.execute("SELECT count(*) FROM runs WHERE finished_at IS NULL OR finished_at=''").fetchone()[0]
            result["model_recovery_required"]=bool(db.execute("SELECT count(*) FROM settings WHERE key IN ('model_checkpoint_required','bayes_rollback_at') AND value<>''").fetchone()[0])
            binding=db.execute("SELECT value FROM settings WHERE key='deployment_identity'").fetchone()
            expected=hashlib.sha256((machine+"\0"+str(STATE)+"\0"+cfg.get("instance_id","")).encode()).hexdigest()
            if binding and binding[0]==expected:
                result["owner"]="VPS-1"
    try:
        heartbeat=json.loads(read(STATE/"service-health.json",32768))
        result["heartbeat"]={k:heartbeat.get(k) for k in ("protocol","last_attempt","last_success","stage","error_code")}
    except FileNotFoundError:
        pass
if pending_migration:
    result["owner"]="handover paused"
print(json.dumps(result,separators=(",",":")))
'''.replace("__LATEST_QUERY__", repr(LATEST_ACTUAL_QUERY)).replace("__WORKER_CONTEXT__", WORKER_CONTEXT)


def timestamp(value):
    if not value:
        return None
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def classify(status):
    """An inactive successful oneshot is normal; use actual filtering evidence."""
    service = status["service"]
    if status["owner"] != "VPS-1":
        return "Paused", "server ownership is " + status["owner"]
    if service.get("ActiveState") in ("active", "activating"):
        return "Running", "mailbox check is in progress"
    latest = status.get("latest_actual")
    if (service.get("ActiveState") == "failed" or service.get("Result") not in (None, "", "success") or
            status["pending"] or status["cursors"] or status["open_runs"] or status["model_recovery_required"]):
        return "Needs attention", "failed service or unresolved mail/model state"
    if latest is None:
        return "Waiting", "no completed server mail run is recorded"
    if latest.get("status") != "ok" or latest.get("errors") != 0 or latest.get("purged") != 0:
        return "Needs attention", "the latest actual mail run did not complete cleanly"
    heartbeat = status.get("heartbeat") or {}
    success = timestamp(heartbeat.get("last_success"))
    finished = timestamp(latest.get("finished_at"))
    if (heartbeat.get("stage") != "ok" or not success or not finished or success < finished or
            heartbeat.get("error_code")):
        return "Needs attention", "mail run and successful heartbeat do not agree"
    age = (timestamp(status["observed_utc"]) - success).total_seconds()
    if age < -60 or age > 45 * 60:
        return "Stale", "no fresh successful mail run within 45 minutes"
    if status["timer"].get("ActiveState") != "active":
        return "Paused", "last run succeeded; automatic schedule is disabled"
    return "Healthy", "mail runs and heartbeat agree; schedule is active"


def age_text(value, observed):
    if not value:
        return "none recorded"
    minutes = max(0, int((timestamp(observed) - timestamp(value)).total_seconds() // 60))
    return (str(minutes) + " minutes ago") if minutes < 120 else ("%.1f hours ago" % (minutes / 60))


def fetch():
    base = Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location("guardian_status_transport", base / "client.py")
    transport = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(transport)
    spec = importlib.util.spec_from_file_location("guardian_pinned_transport", base.parent / "provisioning" / "healthchecks.py")
    pinned = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pinned)
    response = transport.bounded_ssh(pinned.ssh_command(REMOTE), b"", timeout=25, limit=16384)
    result = json.loads(response)
    if result.get("protocol") != 1 or result.get("server") != "VPS-1":
        raise ValueError("unrecognized server status")
    timestamp(result["observed_utc"])
    return result


def main():
    try:
        status = fetch()
        health, detail = classify(status)
        print("Guardian on VPS-1: " + health)
        print(detail + ".")
        print("Observed: " + timestamp(status["observed_utc"]).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"))
        print("Mail worker owner: " + status["owner"])
        policy = status.get("policy") or {}
        print("Policy: " + str(policy.get("mode", "unconfigured")) + "; permanent deletion " +
              ("OFF" if policy.get("purge_enabled") is False else "UNCONFIRMED"))
        heartbeat = status.get("heartbeat") or {}
        print("Last successful check: " + age_text(heartbeat.get("last_success"), status["observed_utc"]))
        latest = status.get("latest_actual")
        if latest:
            print("Latest mail run: #%s, %s; scanned %s, quarantined %s, rescued %s, errors %s, purged %s" %
                  tuple(latest[k] for k in ("id", "status", "scanned", "quarantined", "rescued", "errors", "purged")))
        print("Pending/blocked: %s; reconciliation cursors: %s; model recovery required: %s" %
              (status["pending"], status["cursors"], "yes" if status["model_recovery_required"] else "no"))
        timer = status["timer"]
        print("Automatic checks: " + timer.get("ActiveState", "unknown") + "; next: " +
              (timer.get("NextElapseUSecRealtime") or "not scheduled"))
        backup = status.get("backup")
        print("Latest encrypted application backup: " +
              (age_text(backup["completed_utc"], status["observed_utc"]) if backup else "none completed"))
        return 0 if health in ("Healthy", "Running") else 1
    except Exception:
        print("Guardian on VPS-1: Disconnected")
        print("The server could not be read or its status could not be verified. No local worker was started.")
        return 2


if __name__ == "__main__":
    sys.exit(main())
