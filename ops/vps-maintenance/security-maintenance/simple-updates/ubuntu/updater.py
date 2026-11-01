#!/usr/bin/python3
"""Guardian-aware stable Ubuntu package updates and activation recovery.

Deployment must disable unmanaged unattended package installation. Docker and
image updaters must defer while this updater's durable journal exists.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("ubuntu_docker_primitives", HERE.parent / "docker/updater.py")
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)
e = d.e
# Suppress APT's automatic needrestart hook. Service activation is explicitly
# controlled below, after package installation and while Guardian stays fenced.
e.ENV["NEEDRESTART_SUSPEND"] = "1"
STATE = Path("/var/lib/vps-ubuntu-update")
PENDING = STATE / "pending.json"
d.STATE, d.PENDING = STATE, PENDING
OTHER_PENDING = (Path("/var/lib/vps-docker-simple-update/pending.json"),
                 Path("/var/lib/mail-guardian-admin/auto-image-update/transaction.json"),
                 Path("/var/lib/mail-guardian-application-update/pending.json"))
BOOT_ID = Path("/proc/sys/kernel/random/boot_id")
REBOOT_REQUIRED = Path("/run/reboot-required")
NEEDRESTART = Path("/usr/sbin/needrestart")
NEEDRESTART_CONFIG = Path("/etc/needrestart/conf.d/99-vps-guardian-updates.conf")
NEEDRESTART_CONFIG_BYTES = b'''# Keep the active maintenance owner alive; activation is checked afterward.
$nrconf{override_rc}->{qr(^vps-(?:ubuntu|docker)-update(?:-recover)?\\.service$)} = 0;
$nrconf{override_rc}->{qr(^guardian-(?:image|application)-update(?:-recover)?\\.service$)} = 0;
$nrconf{override_rc}->{qr(^mail-guardian(?:-backup)?@.+\\.service$)} = 0;
'''
TIMERS = d.TIMERS
PRE = ("masking_timers", "backup", "publishing_marker")
FORWARD = ("mutation_pending", "activation_pending", "reboot_requested", "unfence_intent",
           "guardian_run", "restoring_timers")


def codename():
    fields = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            fields[k] = v.strip('"')
    name = fields.get("VERSION_CODENAME", "")
    if fields.get("ID") != "ubuntu" or not re.fullmatch(r"[a-z]+", name):
        raise e.UpdateError("cannot establish Ubuntu release")
    return name


def trusted(version, release):
    return any(bool(getattr(o, "trusted", False)) and o.origin == "Ubuntu" and
               o.archive in (release, release + "-updates", release + "-security") and
               o.component in ("main", "restricted", "universe", "multiverse")
               for o in version.origins)


def package_key(name, cache, inventory):
    """Use dpkg's binary-package identity, including Multi-Arch: same suffixes."""
    if name in inventory:
        return name
    candidate = cache[name].candidate
    base = name.split(":", 1)[0]
    qualified = base + ":" + candidate.architecture
    if qualified in inventory or candidate.record.get("Multi-Arch") == "same":
        return qualified
    return base


def candidates(inventory, release, cache=None, compare=None, holds=None):
    if cache is None:
        import apt
        cache = apt.Cache()
    if compare is None:
        import apt_pkg
        compare = apt_pkg.version_compare
    if holds is None:
        holds = set(e.run(["apt-mark", "showhold"]).stdout.splitlines())
    targets = {}
    for name, current in inventory.items():
        if name.split(":", 1)[0] in e.PACKAGES:
            continue  # the separately coordinated Docker updater owns these
        if name not in cache or cache[name].candidate is None:
            continue  # local obsolete package: no available upgrade
        candidate = cache[name].candidate
        if compare(candidate.version, current) <= 0:
            continue
        if name in holds or name.split(":", 1)[0] in holds:
            raise e.UpdateError("Ubuntu package held: " + name)
        if not trusted(candidate, release):
            raise e.UpdateError("newer candidate has unknown/non-stable origin: " + name)
        targets[name] = candidate.version
    return targets


def apt_plan(targets, inventory, release):
    if not targets:
        return {}
    import apt
    cache = apt.Cache()
    output = e.run(["apt-get", "-s", "--no-remove", "--no-install-recommends", "install"] +
                   [f"{k}={v}" for k, v in sorted(targets.items())]).stdout
    return parse_plan(output, targets, inventory, release, cache,
                      set(e.run(["apt-mark", "showhold"]).stdout.splitlines()))


def parse_plan(output, targets, inventory, release, cache, holds):
    plan = {}
    for row in output.splitlines():
        if row.startswith(("Remv ", "Purg ")):
            raise e.UpdateError("Ubuntu plan requires removals; manual compatibility assessment required")
        if not row.startswith("Inst "):
            continue
        match = re.match(r"^Inst\s+(\S+)\s+(?:\[[^]]+\]\s+)?\((\S+)", row)
        if not match or match[1] not in cache or cache[match[1]].candidate is None:
            raise e.UpdateError("unrecognized Ubuntu install plan")
        name, version = package_key(match[1], cache, inventory), match[2]
        candidate = cache[match[1]].candidate
        if (name in plan or candidate.version != version or not trusted(candidate, release) or
                name in holds or name.split(":", 1)[0] in holds):
            raise e.UpdateError("untrusted, held or changed Ubuntu dependency: " + name)
        plan[name] = version
    if any(plan.get(k) != v for k, v in targets.items()):
        raise e.UpdateError("Ubuntu plan omits exact update targets")
    return plan


def read_pending():
    fd = os.open(PENDING, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or
                stat.S_IMODE(info.st_mode) != 0o600):
            raise e.UpdateError("unsafe Ubuntu update journal")
        raw = os.read(fd, 1048577)
        if len(raw) > 1048576:
            raise e.UpdateError("Ubuntu update journal exceeds limit")
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise e.UpdateError("invalid Ubuntu journal")
        return data
    finally:
        os.close(fd)


def expected_kernel(boot_root=Path("/boot"), system_link=Path("/vmlinuz")):
    boot_root = boot_root.resolve(strict=True)
    link = boot_root / "vmlinuz"
    if not link.exists():
        link = system_link
    info = link.lstat()
    if info.st_uid != 0 or (not stat.S_ISLNK(info.st_mode) and info.st_mode & 0o022):
        raise e.UpdateError("unsafe Ubuntu boot kernel link")
    path = link.resolve(strict=True)
    match = re.fullmatch(r"vmlinuz-([A-Za-z0-9.+_~-]+)", path.name)
    target = path.lstat()
    if (path.parent != boot_root or not stat.S_ISREG(target.st_mode) or
            target.st_uid != 0 or target.st_mode & 0o022 or not match):
        raise e.UpdateError("cannot establish trusted supported Ubuntu boot kernel")
    return match[1]


def boot_id():
    value = BOOT_ID.read_text().strip()
    if not re.fullmatch(r"[0-9a-f-]{36}", value):
        raise e.UpdateError("invalid boot identifier")
    return value


def needrestart_clean(output):
    fields = {}
    for row in output.splitlines():
        if row.startswith("NEEDRESTART-") and ":" in row:
            name, value = row.split(":", 1)
            fields.setdefault(name, []).append(value.strip())
    # Incomplete/unknown activation reports deliberately require a reboot.
    return (fields.get("NEEDRESTART-KSTA") == ["1"] and
            fields.get("NEEDRESTART-UCSTA", ["1"]) == ["1"] and
            not any(fields.get(k) for k in ("NEEDRESTART-SVC", "NEEDRESTART-CONT",
                                            "NEEDRESTART-SESS")))


def activation_clean():
    if REBOOT_REQUIRED.exists() or expected_kernel() != os.uname().release:
        return False
    if not NEEDRESTART.is_file():
        return False
    result = e.run([str(NEEDRESTART), "-b", "-r", "l"], timeout=180, check=False)
    return result.returncode == 0 and needrestart_clean(result.stdout)


def needrestart_configured():
    try:
        info = NEEDRESTART_CONFIG.lstat()
        return (stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
                not info.st_mode & 0o022 and NEEDRESTART_CONFIG.read_bytes() == NEEDRESTART_CONFIG_BYTES)
    except OSError:
        return False


def marker_payload(state):
    return json.dumps({"owner": "vps-ubuntu-auto-update", "transaction": state["transaction"],
                       "worker_authorized": False}).encode()


def publish_marker(state):
    # Same exclusive inode publication as the Docker primitive; separate owner.
    fd, raw = tempfile.mkstemp(prefix=".ubuntu-marker-", dir=e.INSTANCE)
    published = False
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(marker_payload(state))
            out.flush()
            os.fsync(out.fileno())
        os.link(raw, e.MARKER, follow_symlinks=False)
        published = True
        os.unlink(raw)
        e.sync_directory(e.INSTANCE)
    finally:
        if os.path.exists(raw):
            os.unlink(raw)
    return published


def verify_inventory(state, mutated):
    expected = dict(state["inventory"])
    if mutated:
        expected.update(state["plan"])
    if e.run(["dpkg", "--audit"]).stdout.strip() or e.installed_inventory() != expected:
        raise e.UpdateError("Ubuntu package state is incomplete/changed; inspect dpkg and journal")


def request_reboot(state):
    if not state.get("expected_kernel"):
        state["expected_kernel"] = expected_kernel()
    state["phase"] = "reboot_requested"
    d.write_state(state)
    e.run(["systemctl", "reboot", "--no-block"], timeout=30)
    print("Ubuntu activation reboot requested; Guardian remains fenced until boot recovery")


def validate_state(state):
    if (state.get("phase") not in PRE + FORWARD or state.get("timers") != list(TIMERS) or
            not re.fullmatch(r"ubuntu-[0-9a-f]{32}", state.get("transaction", "")) or
            not isinstance(state.get("inventory"), dict) or not state["inventory"] or
            not isinstance(state.get("plan"), dict) or not isinstance(state.get("containers"), dict) or
            not isinstance(state.get("boot_id"), str)):
        raise e.UpdateError("untrusted Ubuntu recovery state")


def recover_locked():
    state = read_pending()
    validate_state(state)
    phase = state["phase"]
    if phase in PRE:
        # These phases are durable before package installation. A crash after
        # publishing the owned marker is recoverable without touching packages.
        verify_inventory(state, False)
        state["plan"] = {}  # no installation could have begun in these phases
        mutated = False
    else:
        verify_inventory(state, True)
        mutated = True
    if d.unit_file_states() != ["masked"] * len(TIMERS) and phase not in ("masking_timers", "restoring_timers"):
        raise e.UpdateError("Ubuntu recovery requires persistent Guardian timer masks")
    if e.unit_state(d.WORKER) == "failed":
        e.run(["systemctl", "reset-failed", d.WORKER])
    d.wait_inactive(d.WORKER)
    d.settle_backup()
    fence = e.acquire_fence()
    frontend = None
    try:
        if any(e.unit_busy(x) for x in e.WORKERS):
            raise e.UpdateError("Guardian active during Ubuntu recovery")
        frontend = e.acquire_frontend_lock()
        e.assert_frontend_lock_held(frontend)
        verify_inventory(state, mutated)
        marker = marker_payload(state)
        exists = os.path.lexists(e.MARKER)
        if exists:
            identity = e.marker_identity(marker)
        elif phase in ("mutation_pending", "activation_pending", "reboot_requested"):
            raise e.UpdateError("Ubuntu recovery marker is missing")
        if mutated and phase in ("mutation_pending", "activation_pending", "reboot_requested"):
            changed_boot = boot_id() != state["boot_id"]
            if (phase == "reboot_requested" or state.get("rehearsal")) and not changed_boot:
                request_reboot(state)
                return
            if changed_boot:
                if os.uname().release != state.get("expected_kernel", expected_kernel()):
                    raise e.UpdateError("booted kernel differs from Ubuntu activation plan")
                if REBOOT_REQUIRED.exists():
                    raise e.UpdateError("reboot-required persists after Ubuntu reboot")
            elif not activation_clean():
                request_reboot(state)
                return
        e.health(state["containers"])
        d.check_ssh_local()
        state["phase"] = "unfence_intent"
        d.write_state(state)
        if exists:
            e.clear_own_marker(marker, expected_identity=identity)
    finally:
        if frontend is not None:
            os.close(frontend)
        os.close(fence)
    state["phase"] = "guardian_run"
    d.write_state(state)
    d.run_worker()
    state["phase"] = "restoring_timers"
    d.write_state(state)
    d.restore_timers()
    PENDING.unlink()
    e.sync_directory(STATE)
    print("Ubuntu package activation verified; actual Guardian run succeeded; timers restored")


def execute(check=False, recover=False, rehearse=False, no_update_only=False):
    if os.geteuid() != 0:
        raise e.UpdateError("root required")
    os.umask(0o077)
    try:
        lock = d.acquire_global()
    except BlockingIOError:
        print("Another updater holds shared lock; retry later")
        return
    try:
        d.ensure_state()
        if any(os.path.lexists(p) for p in OTHER_PENDING):
            raise e.UpdateError("another package/image/application update is pending; resolve its recovery first")
        if os.path.lexists(PENDING):
            if check or no_update_only or rehearse:
                raise e.UpdateError("Ubuntu recovery pending; inspection/rehearsal will not mutate it")
            recover_locked()
            return
        if recover:
            return
        if os.path.lexists(e.MARKER):
            raise e.UpdateError("foreign migration marker; inspect its owner")
        e.run(["apt-get", "-o", "APT::Update::Error-Mode=any", "update"], timeout=900)
        inventory = e.installed_inventory()
        release = codename()
        targets = candidates(inventory, release)
        plan = apt_plan(targets, inventory, release)
        activation_pending = REBOOT_REQUIRED.exists() or expected_kernel() != os.uname().release
        if rehearse and plan:
            raise e.UpdateError("rehearsal refuses pending package updates; apply/assess them first")
        if check:
            print(json.dumps({"mode": "check_only", "release": release, "targets": targets,
                              "plan": plan, "activation_pending": activation_pending}, sort_keys=True))
            return
        if no_update_only and (plan or activation_pending):
            raise e.UpdateError("Ubuntu update/activation candidate exists; no-update-only refuses mutation")
        if not plan and not activation_pending and not rehearse:
            print("Ubuntu packages current; no activation pending")
            return
        if e.run(["dpkg", "--audit"]).stdout.strip():
            raise e.UpdateError("dpkg requires repair before Ubuntu update")
        if d.unit_file_states() != ["enabled"] * len(TIMERS) or not all(e.unit_active(x) for x in TIMERS):
            raise e.UpdateError("Guardian timers must initially be enabled and active")
        before = e.container_snapshot()
        e.health(before)
        if plan:
            e.run(["apt-get", "-y", "--download-only", "--no-remove", "--no-install-recommends", "install"] +
                  [f"{k}={v}" for k, v in sorted(plan.items())], timeout=1200)
        state = {"phase": "masking_timers", "transaction": "ubuntu-" + os.urandom(16).hex(),
                 "inventory": inventory, "plan": plan, "timers": list(TIMERS),
                 "containers": before, "boot_id": boot_id(), "rehearsal": rehearse}
        d.write_state(state)
        e.run(["systemctl", "stop", *TIMERS])
        e.run(["systemctl", "mask", *TIMERS])
        if d.unit_file_states() != ["masked"] * len(TIMERS):
            raise e.UpdateError("Guardian masks not verified")
        d.wait_inactive(d.WORKER)
        d.settle_backup()
        worker_before = d.worker_snapshot()
        state.update(phase="backup", backup=d.fresh_backup())
        d.write_state(state)
        fence = e.acquire_fence()
        frontend = None
        try:
            if any(e.unit_busy(u) for u in e.WORKERS) or d.worker_snapshot() != worker_before:
                raise e.UpdateError("worker changed since coherent backup")
            if e.container_snapshot() != before:
                raise e.UpdateError("Guardian container identity changed since backup")
            frontend = e.acquire_frontend_lock()
            verify_inventory(state, False)
            if candidates(inventory, release) != targets or apt_plan(targets, inventory, release) != plan:
                raise e.UpdateError("Ubuntu candidate/dependency plan changed")
            state["phase"] = "publishing_marker"
            d.write_state(state)
            publish_marker(state)
            state["phase"] = "mutation_pending"
            d.write_state(state)
            e.assert_frontend_lock_held(frontend)
            os.close(frontend)
            frontend = None
            if plan:
                # Normal APT owns its frontend lock. Verify the COMPLETE package
                # inventory afterward; an unexpected concurrent change fences.
                e.run(["apt-get", "-y", "--no-remove", "--no-install-recommends",
                       "-o", "DPkg::Lock::Timeout=120", "-o", "Dpkg::Options::=--force-confdef",
                       "-o", "Dpkg::Options::=--force-confold", "install"] +
                      [f"{k}={v}" for k, v in sorted(plan.items())], timeout=3600)
            frontend = e.acquire_frontend_lock()
            verify_inventory(state, True)
            state.update(phase="activation_pending", expected_kernel=expected_kernel())
            d.write_state(state)
            restart_ok = False
            if NEEDRESTART.is_file() and needrestart_configured() and not rehearse:
                # Automatic mode may restart services; the mailbox remains fenced.
                restart_ok = e.run([str(NEEDRESTART), "-r", "a"], timeout=600, check=False).returncode == 0
            if rehearse or not restart_ok or not activation_clean():
                request_reboot(state)
                return
        finally:
            if frontend is not None:
                os.close(frontend)
            os.close(fence)
        recover_locked()
    finally:
        os.close(lock)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--check", action="store_true")
    modes.add_argument("--recover", action="store_true")
    modes.add_argument("--rehearse", action="store_true", help="fresh backup/fence and real reboot; no package mutation")
    modes.add_argument("--no-update-only", action="store_true")
    args = parser.parse_args()
    try:
        execute(check=args.check, recover=args.recover, rehearse=args.rehearse,
                no_update_only=args.no_update_only)
    except Exception as exc:
        print("Ubuntu update requires inspection:", str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
