#!/usr/bin/python3
"""Installed Docker package updater with guarded forward recovery.

Requires the adjacent auto-updates/docker library from this project. The journal
and migration marker are deliberately left for human recovery on uncertainty.
"""
import fcntl
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "auto-updates/docker"))
import engine as e

GLOBAL_LOCK = Path("/run/mail-guardian-auto-update.lock")
STATE = Path("/var/lib/vps-docker-simple-update")
PENDING = STATE / "pending.json"
BACKUPS = Path("/var/backups/mail-guardian/pilot")
WORKER = "mail-guardian@pilot.service"
BACKUP = "mail-guardian-backup@pilot.service"
TIMERS = e.TIMERS
PACKAGES = e.PACKAGES
FOREIGN_PENDING = (
    Path("/var/lib/vps-ubuntu-update/pending.json"),
    Path("/var/lib/mail-guardian-admin/auto-image-update/transaction.json"),
    Path("/var/lib/mail-guardian-application-update/pending.json"),
)


def foreign_update_pending(inspection=False):
    pending = [str(path) for path in FOREIGN_PENDING if os.path.lexists(path)]
    if not pending:
        return False
    if os.path.lexists(PENDING) or inspection:
        raise e.UpdateError("another updater has pending recovery: " + ", ".join(pending))
    print("Another updater has pending recovery; Docker update deferred: " + ", ".join(pending))
    return True


def guardian_snapshot(deadline=None):
    """Check Guardian's exact containers without rejecting unrelated projects."""
    result = {}
    for name, service in e.EXPECTED.items():
        fmt = ('{{index .Config.Labels "com.docker.compose.project"}}|'
               '{{index .Config.Labels "com.docker.compose.service"}}|'
               '{{.State.Running}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|'
               '{{.Image}}|{{json .Mounts}}|{{json .HostConfig.PortBindings}}')
        output = e.run(["docker", "inspect", "--format", fmt, name],
                       timeout=e.remaining(deadline, 15)).stdout.strip().split("|", 6)
        if len(output) != 7 or output[:4] != ["mail-guardian-pilot", service, "true", "healthy"]:
            raise e.UpdateError(service + " container is not ready")
        result[service] = output[4:]
    return result


# The inherited health checker resolves this function dynamically. Its original
# version rejects any unrelated Docker project, even one not managed by us.
e.container_snapshot = guardian_snapshot


def write_state(data):
    fd, tmp = tempfile.mkstemp(prefix=".state-", dir=STATE)
    try:
        with os.fdopen(fd, "w") as out:
            json.dump(data, out, sort_keys=True)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, PENDING)
        e.sync_directory(STATE)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def acquire_global():
    fd = os.open(GLOBAL_LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        opened = os.fstat(fd)
        current = os.lstat(GLOBAL_LOCK)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != 0 or
                stat.S_IMODE(opened.st_mode) != 0o600 or opened.st_nlink != 1 or
                (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)):
            raise e.UpdateError("unsafe shared update lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        current = os.lstat(GLOBAL_LOCK)
        if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
            raise e.UpdateError("shared update lock replaced")
        return fd
    except BaseException:
        os.close(fd)
        raise


def version_line(value):
    # Ignore Debian epoch, retain upstream major/minor; package revisions remain
    # automatic. Never guess a line for an unrecognized publisher version.
    match = re.match(r"^(?:[0-9]+:)?([0-9]+)\.([0-9]+)(?:[.\-+~]|$)", value)
    if not match:
        raise e.UpdateError("unrecognized Docker upstream version")
    return tuple(map(int, match.groups()))


def patch_candidate(package, current, compare):
    candidate = package.candidate
    if version_line(candidate.version) == version_line(current):
        return candidate
    print("Docker version awaiting manual review: " + candidate.version)
    versions = [v for v in package.versions if version_line(v.version) == version_line(current)
                and compare(v.version, current) > 0]
    from functools import cmp_to_key
    return max(versions, key=cmp_to_key(lambda a, b: compare(a.version, b.version))) if versions else None


def candidates(*, allow_new_lines=False):
    import apt
    import apt_pkg
    cache = apt.Cache()
    release = e.ubuntu_codename()
    held = set(e.run(["apt-mark", "showhold"]).stdout.splitlines())
    baseline, targets = {}, {}
    for name in PACKAGES:
        if name not in cache or not cache[name].is_installed or not cache[name].candidate:
            raise e.UpdateError("missing installed package or candidate: " + name)
        package = cache[name]
        current, candidate = package.installed.version, package.candidate
        baseline[name] = current
        if candidate.version == current:
            continue
        candidate = candidate if allow_new_lines else patch_candidate(package, current, apt_pkg.version_compare)
        if candidate is None:
            continue
        if name in held:
            raise e.UpdateError("package held: " + name)
        if apt_pkg.version_compare(candidate.version, current) <= 0:
            raise e.UpdateError("candidate is not newer: " + name)
        if re.search(r"(?:~|[.+-])(?:rc|alpha|beta|dev|pre)[0-9.+~-]*", candidate.version, re.I):
            raise e.UpdateError("prerelease candidate: " + name)
        if not any(bool(getattr(o, "trusted", False)) and o.origin == "Docker" and o.archive == release and
                   o.component == "stable" and o.site == "download.docker.com"
                   for o in candidate.origins):
            raise e.UpdateError("untrusted Docker candidate: " + name)
        targets[name] = candidate.version
    return baseline, targets


def apt_plan(targets, *, allow_new_lines=False):
    """Resolve exact signed Docker/Ubuntu dependencies without removals."""
    import apt
    release = e.ubuntu_codename()
    command = ["apt-get", "-s", "--no-remove", "--no-install-recommends", "install"]
    output = e.run(command + [f"{name}={version}" for name, version in targets.items()]).stdout
    plan = {}
    for row in output.splitlines():
        if row.startswith(("Remv ", "Purg ")):
            raise e.UpdateError("APT plan removes packages")
        if row.startswith("Inst "):
            match = re.match(r"^Inst\s+(\S+)\s+(?:\[[^]]+\]\s+)?\((\S+)", row)
            if not match or match.group(1) in plan:
                raise e.UpdateError("unrecognized APT install plan")
            plan[match.group(1)] = match.group(2)
    if not plan or any(plan.get(name) != version for name, version in targets.items()):
        raise e.UpdateError("APT plan does not contain exact Docker targets")
    cache = apt.Cache()
    held = set(e.run(["apt-mark", "showhold"]).stdout.splitlines())
    for name, version in plan.items():
        if name in held or name not in cache or not cache[name].candidate:
            raise e.UpdateError("held or changed dependency: " + name)
        selected = cache[name].candidate
        if selected.version != version:
            choices = [v for v in getattr(cache[name], 'versions', ()) if v.version == version]
            if name not in targets or len(choices) != 1:
                raise e.UpdateError("held or changed dependency: " + name)
            selected = choices[0]
        installed = getattr(cache[name], 'installed', None)
        if not allow_new_lines and name in PACKAGES and installed and version_line(version) != version_line(installed.version):
            raise e.UpdateError("Docker dependency plan crosses a manually reviewed version line: " + name)
        origins = selected.origins
        def trusted(origin):
            return bool(getattr(origin, "trusted", False)) and (
                (origin.origin == "Docker" and origin.archive == release and
                 origin.component == "stable" and origin.site == "download.docker.com") or
                (origin.origin == "Ubuntu" and origin.archive in
                 (release, release + "-updates", release + "-security")))
        if not any(trusted(origin) for origin in origins):
            raise e.UpdateError("untrusted dependency source: " + name)
    return plan


def properties(unit):
    output = e.run(["systemctl", "show", unit, "-p", "InvocationID", "-p", "Result",
                    "-p", "ExecMainCode", "-p", "ExecMainStatus"]).stdout
    return dict(row.split("=", 1) for row in output.splitlines() if "=" in row)


def wait_inactive(unit, timeout=7500):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        state = e.unit_state(unit)
        if state == "inactive":
            return
        if state == "failed":
            raise e.UpdateError(unit + " failed")
        time.sleep(2)
    raise e.UpdateError(unit + " did not finish")


def settle_backup(timeout=1000):
    """Wait for an active capture; cancel only inactive/failed/queued retries."""
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        output = e.run(["systemctl", "show", BACKUP, "-p", "ActiveState", "-p", "SubState"]).stdout
        fields = dict(row.split("=", 1) for row in output.splitlines() if "=" in row)
        active, sub = fields.get("ActiveState"), fields.get("SubState")
        if active in ("inactive", "failed") or (active == "activating" and sub == "auto-restart"):
            e.run(["systemctl", "stop", BACKUP])
            if e.unit_state(BACKUP) != "inactive":
                raise e.UpdateError("backup retry did not stop")
            return
        if active not in ("active", "activating", "deactivating"):
            raise e.UpdateError("unknown backup service state")
        time.sleep(2)
    raise e.UpdateError("backup did not settle")


def fresh_backup():
    old = {p.name for p in BACKUPS.glob("*.age")}
    e.run(["systemctl", "start", BACKUP], timeout=1000)
    wait_inactive(BACKUP)
    # Foreground systemctl start succeeded. Inactive oneshots may already be
    # garbage-collected; prove the backup with its fresh checked artifact below.
    added = [p for p in BACKUPS.glob("*.age") if p.name not in old]
    if len(added) != 1:
        raise e.UpdateError("cannot identify fresh backup")
    file = added[0]
    info = file.lstat()
    receipt = file.with_name(file.name + ".sha256")
    receipt_info = receipt.lstat()
    if any(not stat.S_ISREG(x.st_mode) or x.st_uid != 0 or x.st_nlink != 1 for x in (info, receipt_info)):
        raise e.UpdateError("unsafe backup or receipt")
    fields = receipt.read_text().strip().split(None, 1)
    digest = hashlib.sha256()
    with file.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    if len(fields) != 2 or fields[0] != digest.hexdigest() or fields[1].lstrip("*") != file.name:
        raise e.UpdateError("fresh backup checksum failed")
    return file.name


def worker_snapshot():
    helper = Path(__file__).resolve().with_name("worker_evidence.py")
    result = e.run(["sudo", "-n", "-u", "mg-pilot", "/usr/bin/python3", "-I", str(helper)], timeout=30)
    evidence = json.loads(result.stdout)
    if not isinstance(evidence, dict) or not isinstance(evidence.get("actual"), dict):
        raise e.UpdateError("invalid worker application evidence")
    return evidence


def worker_time(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z", value):
        raise e.UpdateError("invalid worker evidence timestamp")
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def verify_worker_run(previous, result, requested, now):
    try:
        before, actual, beat = previous["actual"], result["actual"], result["heartbeat"]
        started, finished = worker_time(actual["started_at"]), worker_time(actual["finished_at"])
        attempt, success = worker_time(beat["last_attempt"]), worker_time(beat["last_success"])
        valid = (type(actual["id"]) is int and actual["id"] > before["id"] and
                 actual["command"] == "run" and actual["dry_run"] == 0 and actual["status"] == "ok" and
                 actual["errors"] == 0 and actual["purged"] == 0 and result["latest_id"] == actual["id"] and
                 beat["protocol"] == 1 and beat["stage"] == "ok" and not beat.get("error_code") and
                 requested <= attempt <= started <= finished <= success <= now + 5 and
                 all(result[k] == 0 for k in ("open_runs", "pending_messages", "reconciliations")) and
                 not result["model_checkpoint"])
    except (KeyError, TypeError, ValueError):
        valid = False
    if not valid:
        raise e.UpdateError("fresh actual Guardian run/heartbeat was not verified")


def run_worker():
    previous = worker_snapshot()
    requested = time.time()
    e.run(["systemctl", "start", WORKER], timeout=7300)
    wait_inactive(WORKER)
    verify_worker_run(previous, worker_snapshot(), requested, time.time())


def check_ssh_local():
    """Check the local daemon and SSH banner, not external connectivity or login."""
    e.run(["systemctl", "is-active", "--quiet", "ssh.service"], timeout=10)
    with socket.create_connection(("127.0.0.1", 22), timeout=5) as conn:
        conn.settimeout(5)
        banner = conn.recv(256)
    if not banner.startswith(b"SSH-2.0-"):
        raise e.UpdateError("local SSH banner check failed")


def unit_file_states():
    result = e.run(["systemctl", "is-enabled", *TIMERS], check=False)
    values = result.stdout.splitlines()
    if len(values) != len(TIMERS):
        raise e.UpdateError("cannot establish Guardian timer enablement")
    return values


def ensure_state():
    STATE.mkdir(mode=0o700, exist_ok=True)
    st = STATE.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o700:
        raise e.UpdateError("unsafe updater state directory")


def read_pending():
    fd = os.open(PENDING, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        current = os.lstat(PENDING)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or
                (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino)):
            raise e.UpdateError("untrusted pending update record")
        content = os.read(fd, 65537)
        if len(content) > 65536:
            raise e.UpdateError("pending update record too large")
        data = json.loads(content)
        if not isinstance(data, dict):
            raise e.UpdateError("invalid pending update record")
        return data
    finally:
        os.close(fd)


def recover_pre_mutation_locked():
    """Recover only a verified transaction that could not have started dpkg."""
    if not os.path.lexists(PENDING):
        return False
    state = read_pending()
    if (state.get("phase") not in ("masking_timers", "backup") or
            state.get("timers") != list(TIMERS) or os.path.lexists(e.MARKER)):
        raise e.UpdateError("update requires manual recovery")
    baseline = state.get("baseline")
    if (not isinstance(baseline, dict) or set(baseline) != set(PACKAGES) or
            not all(isinstance(v, str) and v for v in baseline.values())):
        raise e.UpdateError("untrusted pre-update package baseline")
    if e.run(["dpkg", "--audit"]).stdout.strip():
        raise e.UpdateError("dpkg not clean during recovery")
    inventory = e.installed_inventory()
    if any(inventory.get(name) != version for name, version in baseline.items()):
        raise e.UpdateError("packages changed since update began")
    wait_inactive(WORKER)
    settle_backup()
    fence = e.acquire_fence()
    try:
        if os.path.lexists(e.MARKER) or any(e.unit_busy(unit) for unit in e.WORKERS):
            raise e.UpdateError("Guardian changed during recovery")
        before = e.container_snapshot()
        e.health(before)
        check_ssh_local()
        states = unit_file_states()
        if any(value not in ("enabled", "masked") for value in states):
            raise e.UpdateError("unexpected timer configuration during recovery")
        e.run(["systemctl", "unmask", *TIMERS])
        if unit_file_states() != ["enabled"] * len(TIMERS):
            raise e.UpdateError("cannot restore timer enablement")
    finally:
        os.close(fence)
    e.run(["systemctl", "start", *TIMERS])
    if not all(e.unit_active(timer) for timer in TIMERS):
        raise e.UpdateError("could not restore Guardian timers")
    PENDING.unlink()
    e.sync_directory(STATE)
    print("Recovered pre-mutation interruption; Guardian timers restored")
    return True


def restore_timers():
    states = unit_file_states()
    if any(value not in ("enabled", "masked") for value in states):
        raise e.UpdateError("unexpected Guardian timer state")
    e.run(["systemctl", "unmask", *TIMERS])
    if unit_file_states() != ["enabled"] * len(TIMERS):
        raise e.UpdateError("timer enablement changed while unmasking")
    e.run(["systemctl", "start", *TIMERS])
    if not all(e.unit_active(timer) for timer in TIMERS):
        raise e.UpdateError("could not restore Guardian timers")


def recover_forward_locked(state):
    """Resume only a fully applied package set with healthy current state."""
    phase = state.get("phase")
    allowed = ("mutation_pending", "unfence_intent", "guardian_run", "unmasking_timers_after_verified_run")
    if phase not in allowed or state.get("timers") != list(TIMERS):
        raise e.UpdateError("update requires manual recovery")
    baseline, targets, plan = state.get("baseline"), state.get("targets"), state.get("plan")
    before, transaction = state.get("containers"), state.get("transaction")
    if (not isinstance(baseline, dict) or set(baseline) != set(PACKAGES) or
            not isinstance(targets, dict) or not targets or not set(targets).issubset(PACKAGES) or
            not isinstance(plan, dict) or not all(plan.get(k) == v for k, v in targets.items()) or
            not all(isinstance(v, str) and v for v in list(baseline.values()) + list(plan.values())) or
            not isinstance(before, dict) or set(before) != {"redis", "rspamd", "unbound"} or
            not isinstance(transaction, str) or not re.fullmatch(r"simple-docker-packages-[A-Za-z0-9_-]+", transaction)):
        raise e.UpdateError("untrusted forward recovery plan")
    expected = dict(baseline)
    expected.update(plan)
    if phase != "unmasking_timers_after_verified_run" and unit_file_states() != ["masked"] * len(TIMERS):
        raise e.UpdateError("Guardian timers are not fenced")
    if e.unit_state(WORKER) == "failed":
        e.run(["systemctl", "reset-failed", WORKER])
    wait_inactive(WORKER)
    settle_backup()
    fence = e.acquire_fence()
    frontend = None
    try:
        if any(e.unit_busy(unit) for unit in e.WORKERS):
            raise e.UpdateError("Guardian active during forward recovery")
        frontend = e.acquire_frontend_lock()
        e.assert_frontend_lock_held(frontend)
        if e.run(["dpkg", "--audit"]).stdout.strip():
            raise e.UpdateError("dpkg requires manual recovery")
        inventory = e.installed_inventory()
        if any(inventory.get(name) != version for name, version in expected.items()):
            raise e.UpdateError("Docker package update is incomplete")
        e.health(before)
        check_ssh_local()
        marker_exists = os.path.lexists(e.MARKER)
        if phase == "mutation_pending" and not marker_exists:
            raise e.UpdateError("expected migration marker is missing")
        if phase in ("guardian_run", "unmasking_timers_after_verified_run") and marker_exists:
            raise e.UpdateError("unexpected migration marker")
        if marker_exists:
            marker = json.dumps({"owner": "vps-docker-auto-update", "transaction": transaction,
                                 "worker_authorized": False}).encode()
            identity = e.marker_identity(marker)
            state["phase"] = "unfence_intent"
            write_state(state)
            e.clear_own_marker(marker, expected_identity=identity)
        if phase != "unmasking_timers_after_verified_run":
            state["phase"] = "guardian_run"
            write_state(state)
    finally:
        if frontend is not None:
            os.close(frontend)
        os.close(fence)
    if phase != "unmasking_timers_after_verified_run":
        run_worker()
        state["phase"] = "unmasking_timers_after_verified_run"
        write_state(state)
    restore_timers()
    PENDING.unlink()
    e.sync_directory(STATE)
    print("Recovered Docker update forward; Guardian timers restored")


def recover_pending_locked():
    if not os.path.lexists(PENDING):
        return False
    state = read_pending()
    if state.get("phase") in ("masking_timers", "backup"):
        return recover_pre_mutation_locked()
    recover_forward_locked(state)
    return True


def recover():
    if os.geteuid() != 0:
        raise e.UpdateError("root required")
    try:
        lock = acquire_global()
    except BlockingIOError:
        print("Another Guardian update holds the shared lock; retry later")
        return
    try:
        ensure_state()
        if foreign_update_pending():
            return
        recover_pending_locked()
    finally:
        os.close(lock)


def execute(check_only=False, no_update_only=False, allow_new_lines=False):
    if os.geteuid() != 0:
        raise e.UpdateError("root required")
    try:
        lock = acquire_global()
    except BlockingIOError:
        print("Another Guardian update holds the shared lock; retry later")
        return
    try:
        ensure_state()
        if foreign_update_pending(inspection=check_only or no_update_only):
            return
        if os.path.lexists(PENDING):
            if check_only or no_update_only:
                raise e.UpdateError("unresolved update; inspection mode will not recover it")
            recover_pending_locked()
            return
        if os.path.lexists(e.MARKER):
            raise e.UpdateError("unresolved migration; manual recovery required")
        e.run(["apt-get", "update"], timeout=900)
        get_candidates = lambda: candidates(allow_new_lines=True) if allow_new_lines else candidates()
        get_plan = lambda targets: apt_plan(targets, allow_new_lines=True) if allow_new_lines else apt_plan(targets)
        baseline, targets = get_candidates()
        if check_only:
            if targets:
                get_plan(targets)
            print(json.dumps({"mode": "check_only", "installed": baseline, "candidates": targets}, sort_keys=True))
            return
        if not targets:
            print("Docker packages current")
            return
        if no_update_only:
            raise e.UpdateError("candidate exists; no-update-only mode cannot install")
        plan = get_plan(targets)
        if e.run(["dpkg", "--audit"]).stdout.strip():
            raise e.UpdateError("dpkg audit failed")
        if (not all(e.unit_active(timer) for timer in TIMERS) or
                unit_file_states() != ["enabled"] * len(TIMERS)):
            raise e.UpdateError("both Guardian timers must be enabled and active")
        before = e.container_snapshot()
        e.health(before)
        work = Path(tempfile.mkdtemp(prefix="packages-", dir=STATE))
        packages = e.save_packages(work, targets, targets)
        e.sync_directory(work)
        transaction = "simple-docker-" + work.name
        state = {"phase": "masking_timers", "baseline": baseline, "targets": targets, "plan": plan,
                 "packages": packages, "timers": list(TIMERS), "containers": before,
                 "transaction": transaction}
        write_state(state)
        e.run(["systemctl", "stop", *TIMERS])
        # A stopped enabled timer returns at reboot. Persistent instance masks
        # prevent an unattended run after a crash, including during postflight.
        # The journal is durable before the first mask is attempted.
        e.run(["systemctl", "mask", *TIMERS])
        if unit_file_states() != ["masked"] * len(TIMERS):
            raise e.UpdateError("timer masks could not be verified")
        wait_inactive(WORKER)
        settle_backup()
        worker_before = worker_snapshot()
        state.update(phase="backup", backup=fresh_backup())
        write_state(state)
        fence = e.acquire_fence()
        frontend = None
        try:
            if any(e.unit_busy(u) for u in e.WORKERS) or worker_snapshot() != worker_before:
                raise e.UpdateError("worker or backup changed since capture")
            if e.container_snapshot() != before:
                raise e.UpdateError("container identities changed")
            frontend = e.acquire_frontend_lock()
            if get_candidates() != (baseline, targets):
                raise e.UpdateError("candidates changed")
            if get_plan(targets) != plan:
                raise e.UpdateError("APT dependency plan changed")
            inventory = e.installed_inventory()
            state["phase"] = "publishing_marker"
            write_state(state)
            marker = e.create_marker(transaction)
            marker_id = e.marker_identity(marker)
            state["phase"] = "mutation_pending"
            write_state(state)
            for path, digest in packages.values():
                if hashlib.sha256(Path(path).read_bytes()).hexdigest() != digest:
                    raise e.UpdateError("package changed")
            e.assert_frontend_lock_held(frontend)
            # APT must own its frontend lock itself. Exact simulated versions
            # remain pinned; a concurrent package action causes later inventory
            # verification to fail closed rather than silently pass.
            os.close(frontend)
            frontend = None
            e.run(["apt-get", "-y", "--no-remove", "--no-install-recommends",
                   "-o", "DPkg::Lock::Timeout=120", "-o", "Dpkg::Options::=--force-confdef",
                   "-o", "Dpkg::Options::=--force-confold", "install"] +
                  [f"{name}={version}" for name, version in plan.items()], timeout=1200)
            frontend = e.acquire_frontend_lock()
            e.assert_frontend_lock_held(frontend)
            if (not e.inventory_matches(inventory, e.installed_inventory(), plan) or
                    e.run(["dpkg", "--audit"]).stdout.strip()):
                raise e.UpdateError("installed package verification failed")
            e.health(before)
            check_ssh_local()
            state["phase"] = "unfence_intent"
            write_state(state)
            e.clear_own_marker(marker, expected_identity=marker_id)
        finally:
            if frontend is not None:
                os.close(frontend)
            os.close(fence)
        state["phase"] = "guardian_run"
        write_state(state)
        run_worker()
        state["phase"] = "unmasking_timers_after_verified_run"
        write_state(state)
        restore_timers()
        PENDING.unlink()
        e.sync_directory(STATE)
        print("Docker packages updated; Guardian worker succeeded")
    finally:
        os.close(lock)


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["--recover"]:
            recover()
        elif sys.argv[1:] == ["--check"]:
            execute(check_only=True)
        elif sys.argv[1:] == ["--check", "--allow-new-lines"]:
            execute(check_only=True, allow_new_lines=True)
        elif sys.argv[1:] == ["--allow-new-lines"]:
            execute(allow_new_lines=True)
        elif sys.argv[1:] == ["--no-update-only"]:
            execute(no_update_only=True)
        elif not sys.argv[1:]:
            execute()
        else:
            raise e.UpdateError("usage: updater.py [--check|--no-update-only|--recover|--allow-new-lines|--check --allow-new-lines]")
    except Exception as exc:
        print("Docker update did not complete; inspect journal, pending state and migration marker:", str(exc), file=sys.stderr)
        sys.exit(1)
