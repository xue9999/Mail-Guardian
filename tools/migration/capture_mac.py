#!/usr/bin/env python3
"""Capture a paused Mac Guardian, normally for an isolated rehearsal, then resume it.

Default invocation only previews. --capture explicitly pauses this Mac's Guardian
LaunchAgents, closes its GUI and stops its Rspamd writer while holding guardian.lock.
--keep-paused leaves the Mac disabled for an explicitly coordinated handover.
It does not revoke mailbox access or independently establish ownership. Do not
start a VPS mail worker without the separate owner fence and recovery checks.
No IMAP password is read or included.
"""

import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import tomllib

LABELS = ("pl.o2.mail-guardian", "pl.o2.mail-guardian-ui")
MAX_FILES = 50_000
MAX_BYTES = 512 << 20


class CaptureError(Exception):
    pass


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def launchd_disabled(text, label):
    """Read both launchctl boolean and current macOS enabled/disabled formats.

    An absent override uses launchd's default enabled state. A present entry
    with an unknown representation is not evidence of either state.
    """
    quoted = '"' + label + '"'
    matches = re.findall(r'(?m)^\s*' + re.escape(quoted) + r'\s*=>\s*([^\n]+)$', text)
    if not matches:
        if quoted in text:
            raise CaptureError("A Guardian LaunchAgent has an unrecognized disabled-state entry.")
        return False
    if len(matches) != 1:
        raise CaptureError("A Guardian LaunchAgent has duplicate disabled-state entries.")
    value = matches[0].strip()
    if value.endswith(","):
        value = value[:-1].strip()
    if value in ("true", "disabled"):
        return True
    if value in ("false", "enabled"):
        return False
    raise CaptureError("A Guardian LaunchAgent has an unrecognized disabled-state entry.")


def command(args, *, env=None, check=True, timeout=30):
    try:
        result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=env, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise CaptureError("A capture dependency was unavailable or timed out.") from None
    if check and result.returncode:
        raise CaptureError("A capture dependency failed; its diagnostics were suppressed.")
    return result


def write_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def json_private(path, value):
    write_private(path, (json.dumps(value, indent=2) + "\n").encode())


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_json_private(path, value):
    """Publish one complete, private receipt without replacing an existing object."""
    fd, temporary = tempfile.mkstemp(prefix=".pause-receipt-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write((json.dumps(value, indent=2) + "\n").encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path, follow_symlinks=False)
        os.unlink(temporary)
        temporary = None
        sync_directory(path.parent)
    finally:
        if temporary is not None:
            os.unlink(temporary)


def copy_file(source, destination, maximum=MAX_BYTES):
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as incoming:
        before = os.fstat(incoming.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_size < 0 or before.st_size > maximum):
            raise CaptureError("The capture source contains an unsupported file.")
        digest = hashlib.sha256()
        outgoing_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(outgoing_fd, "wb") as outgoing:
            total = 0
            while True:
                data = incoming.read(min(1 << 20, maximum - total + 1))
                if not data:
                    break
                total += len(data)
                if total > maximum:
                    raise CaptureError("Capture byte limit exceeded.")
                outgoing.write(data)
                digest.update(data)
            outgoing.flush()
            os.fsync(outgoing.fileno())
        after = os.fstat(incoming.fileno())
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or total != before.st_size:
            raise CaptureError("A capture source changed while copying.")
        return digest.hexdigest(), total


def copy_tree(source, destination, counts=None):
    """Copy a quiescent, private tree without accepting links or special entries."""
    if counts is None:
        counts = [0, 0]
    info = source.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise CaptureError("A captured directory is not a real directory.")
    destination.mkdir(mode=0o700)
    for item in sorted(source.iterdir()):
        info = item.lstat()
        if stat.S_ISDIR(info.st_mode):
            copy_tree(item, destination / item.name, counts)
        elif stat.S_ISREG(info.st_mode):
            counts[0] += 1
            if counts[0] > MAX_FILES:
                raise CaptureError("Capture file limit exceeded.")
            _, size = copy_file(item, destination / item.name, MAX_BYTES - counts[1])
            counts[1] += size
        else:
            raise CaptureError("A captured directory contains a link or special file.")
    return counts


def guardian_processes():
    result = command(["/bin/ps", "-axo", "pid=,comm="])
    processes = []
    for line in result.stdout.decode().splitlines():
        fields = line.strip().split(None, 1)
        if len(fields) != 2:
            continue
        name = Path(fields[1]).name
        if (name == "O2MailGuardianApp" or name == "guardian" or name.startswith("guardian.")
                or (name.startswith("guardian-") and name != "guardian-recovery")):
            processes.append((int(fields[0]), name))
    return processes


def snapshot_database(source, destination):
    incoming = sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)
    outgoing = None
    try:
        pages = incoming.execute("PRAGMA page_count").fetchone()[0]
        page_size = incoming.execute("PRAGMA page_size").fetchone()[0]
        if pages * page_size > 64 << 20:
            raise CaptureError("Source database exceeds the 64 MiB capture limit.")
        if incoming.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise CaptureError("Source database integrity check failed.")
        unresolved = incoming.execute(
            "SELECT COUNT(*) FROM messages WHERE status LIKE 'pending%' OR status IN ('blocked','ambiguous')"
        ).fetchone()[0]
        if unresolved:
            raise CaptureError("Source database has unresolved mailbox operations.")
        latest = incoming.execute(
            "SELECT status,errors FROM runs WHERE command='run' AND dry_run=0 ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if latest != ("ok", 0):
            raise CaptureError("The latest actual source run is not successful.")
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        outgoing = sqlite3.connect(destination)
        incoming.backup(outgoing)
        # SQLite backup preserves the source WAL-mode header. The offline
        # inspector requires an independently usable main image (header 1,1),
        # without importing the live journal mode or requiring sidecars.
        if outgoing.execute("PRAGMA journal_mode=DELETE").fetchone()[0] != "delete":
            raise CaptureError("Captured database could not leave WAL mode.")
        if outgoing.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise CaptureError("Captured database integrity check failed.")
        outgoing.commit()
    finally:
        if outgoing is not None:
            outgoing.close()
        incoming.close()
    with destination.open("rb") as stream:
        os.fsync(stream.fileno())


class MacPause:
    """Reversible local rehearsal boundary; deliberately not a cross-host fence."""

    def __init__(self, home, cfg, baseline, run=command):
        self.home, self.cfg, self.baseline, self.run = home, cfg, baseline, run
        self.domain = "gui/" + str(os.getuid())
        self.original = {}
        self.changed = []
        self.scanner_stopped = False
        self.gui_was_running = False
        self.env = dict(os.environ)
        self.env["PATH"] = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
        runtime = Path(cfg["runtime"]["compose_file"]).parent.parent
        if runtime.name != "o2-mail-guardian":
            raise CaptureError("The source Compose path has an unsupported runtime layout.")
        self.env["GUARDIAN_RUNTIME_DIR"] = str(runtime)
        # Match config.DefaultRuntimeDir() inside the recovery subprocess to
        # this explicitly configured existing stack, including custom XDG roots.
        self.env["XDG_CONFIG_HOME"] = str(runtime.parent)
        docker = shutil.which("docker", path=self.env["PATH"])
        if not docker:
            raise CaptureError("Docker is unavailable.")
        self.compose = [docker, "--context", "colima", "compose", "--project-name", "o2-mail-guardian",
                        "--file", cfg["runtime"]["compose_file"]]

    def launch(self, *args, **kwargs):
        return self.run(["/bin/launchctl", *args], **kwargs)

    def inspect(self):
        disabled = self.launch("print-disabled", self.domain).stdout.decode()
        for label in LABELS:
            exists = self.launch("print", self.domain + "/" + label, check=False).returncode == 0
            self.original[label] = {"loaded": exists, "disabled": launchd_disabled(disabled, label)}
        json_private(self.baseline / "launchd-state.json", self.original)
        processes = guardian_processes()
        self.gui_was_running = any(name == "O2MailGuardianApp" for _, name in processes)
        if any(name != "O2MailGuardianApp" for _, name in processes):
            raise CaptureError("A Guardian command is active; wait for it to finish before capture.")
        running = self.run(self.compose + ["ps", "--status", "running", "--services"], env=self.env).stdout.decode().splitlines()
        if "redis" not in running or "rspamd" not in running:
            raise CaptureError("The existing Mac Redis/Rspamd stack is not running.")
        # This immutable receipt is durably published before any local change.
        atomic_json_private(self.baseline / "pause-receipt.json", {
            "version": 1, "uid": os.getuid(), "home": str(self.home), "created_utc": utc(),
            "launchd": self.original, "gui_was_running": self.gui_was_running,
            "scanner_was_running": True, "keep_paused": bool(getattr(self, "keep_paused", False)),
            "source_config_sha256": hashlib.sha256((self.baseline.parent / "config.toml").read_bytes()).hexdigest(),
        })

    def pause(self):
        self.inspect()
        for label in LABELS:
            self.launch("disable", self.domain + "/" + label)
            self.changed.append(label)
        if any(name != "O2MailGuardianApp" for _, name in guardian_processes()):
            raise CaptureError("A Guardian command started during preparation; capture stopped.")
        if guardian_processes():
            self.run(["/usr/bin/osascript", "-e", 'tell application id "pl.o2.mail-guardian.app" to quit'])
            deadline = time.monotonic() + 15
            while guardian_processes() and time.monotonic() < deadline:
                time.sleep(0.2)
            if guardian_processes():
                raise CaptureError("Guardian did not close gracefully; capture stopped.")
        for label in LABELS:
            if self.original[label]["loaded"]:
                self.launch("bootout", self.domain + "/" + label)
        if guardian_processes():
            raise CaptureError("A Guardian process remains; capture stopped.")
        status = self.run(self.compose + ["ps", "--status", "running", "--services"], env=self.env)
        running = status.stdout.decode().splitlines()
        if "redis" not in running or "rspamd" not in running:
            raise CaptureError("The existing Mac Redis/Rspamd stack is not running.")
        # Mark before stop: a timed-out command may already have stopped Rspamd.
        self.scanner_stopped = True
        self.run(self.compose + ["stop", "--timeout", "30", "rspamd"], env=self.env, timeout=45)
        self.assert_quiescent()

    def assert_quiescent(self):
        if guardian_processes():
            raise CaptureError("A Guardian process appeared during capture.")
        result = self.run(self.compose + ["exec", "-T", "redis", "redis-cli", "--raw", "CLIENT", "LIST"], env=self.env)
        clients = result.stdout.decode().strip().splitlines()
        if len(clients) != 1:
            raise CaptureError("Another Redis client is present; capture stopped.")

    def assert_paused(self):
        self.assert_quiescent()
        disabled = self.launch("print-disabled", self.domain).stdout.decode()
        for label in LABELS:
            if not launchd_disabled(disabled, label):
                raise CaptureError("A Guardian LaunchAgent is not disabled.")
            if self.launch("print", self.domain + "/" + label, check=False).returncode == 0:
                raise CaptureError("A Guardian LaunchAgent remains loaded.")
        running = self.run(self.compose + ["ps", "--status", "running", "--services"], env=self.env).stdout.decode().splitlines()
        if "rspamd" in running or "redis" not in running:
            raise CaptureError("The paused scanner/model state could not be verified.")

    def resume(self):
        failures = []
        if self.scanner_stopped:
            try:
                self.run(self.compose + ["start", "--wait", "rspamd"], env=self.env, timeout=90)
            except CaptureError:
                failures.append("Rspamd")
        # If Rspamd could not resume, do not start workers against an unhealthy stack.
        if not failures:
            for label in reversed(self.changed):
                previous = self.original[label]
                try:
                    if not previous["disabled"]:
                        self.launch("enable", self.domain + "/" + label)
                    loaded = self.launch("print", self.domain + "/" + label, check=False).returncode == 0
                    if previous["loaded"] and not loaded:
                        self.launch("bootstrap", self.domain, str(self.home / "Library/LaunchAgents" / (label + ".plist")))
                except CaptureError:
                    failures.append(label)
            if (getattr(self, "gui_was_running", False) and not self.original[LABELS[1]]["loaded"]
                    and not any(name == "O2MailGuardianApp" for _, name in guardian_processes())):
                try:
                    self.run(["/usr/bin/open", "-a", str(self.home / "Applications/O2 Mail Guardian.app")])
                except CaptureError:
                    failures.append("Guardian GUI")
        if failures:
            raise CaptureError("Mac restoration needs attention: " + ", ".join(failures))


def publish_capture(output, report, *, keep_paused):
    report["mac_state"] = "paused" if keep_paused else "resumed"
    report["files"] = {str(p.relative_to(output)): hashlib.sha256(p.read_bytes()).hexdigest()
                       for p in sorted(output.rglob("*")) if p.is_file() and p.name != "INCOMPLETE"}
    json_private(output / "capture.json", report)
    description = (b"Capture complete. Mac remains paused; independent mailbox ownership still requires operator checks.\n"
                   if keep_paused else b"Rehearsal capture only. Mac remains the mailbox owner.\n")
    write_private(output / "COMPLETE", description)
    (output / "INCOMPLETE").unlink()
    sync_directory(output)


def invalidate_publication(output):
    # A late directory-sync failure must not leave a usable COMPLETE marker
    # after the error path has resumed the Mac. Preserve captured evidence.
    try:
        write_private(output / "INCOMPLETE", b"Capture publication failed. Do not activate a server worker from this stage.\n")
    except OSError:
        pass
    try:
        (output / "COMPLETE").unlink()
    except OSError:
        pass
    try:
        sync_directory(output)
    except OSError:
        pass


def capture(home, configuration, recovery, output, *, keep_paused=False):
    if sys.platform != "darwin":
        raise CaptureError("This capture runs only on macOS.")
    if output.exists() or output.is_symlink() or output.parent.resolve() != output.parent:
        raise CaptureError("Output must be a new directory beneath a real parent.")
    parent = output.parent.stat()
    if parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) & 0o077:
        raise CaptureError("Output parent must be private and owned by this user.")
    output.mkdir(mode=0o700)
    write_private(output / "INCOMPLETE", b"Capture incomplete. Do not activate a server worker from this stage.\n")
    baseline = output / "baseline"
    baseline.mkdir(mode=0o700)
    copy_file(configuration, output / "config.toml", 64 << 10)
    cfg = tomllib.loads((output / "config.toml").read_text())
    copy_file(home / ".local/bin/o2-mail-guardian/guardian", baseline / "guardian")
    for label in LABELS:
        path = home / "Library/LaunchAgents" / (label + ".plist")
        if path.exists():
            copy_file(path, baseline / path.name)
    pauser = MacPause(home, cfg, baseline)
    pauser.keep_paused = keep_paused
    scope = ("handover capture; Mac left paused; independent owner fence not established; no IMAP password included"
             if keep_paused else "rehearsal-only; Mac resumes ownership; no IMAP password included")
    report = {"version": 1, "scope": scope, "started_utc": utc()}
    leave_paused = False
    try:
        pauser.pause()
        fd = os.open(Path(cfg["runtime"]["data_dir"]) / "guardian.lock", os.O_RDWR | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as lock:
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise CaptureError("Guardian's run lock is held; capture stopped.") from None
            pauser.assert_quiescent()
            if hashlib.sha256(configuration.read_bytes()).digest() != hashlib.sha256((output / "config.toml").read_bytes()).digest():
                raise CaptureError("The source configuration changed before capture; retry from a new stage.")
            snapshot_database(Path(cfg["runtime"]["database"]), output / "original.db")
            preparation = command([str(recovery), "prepare-snapshot", "--config", str(output / "config.toml"),
                                   "--source", str(output / "original.db"), "--database", str(output / "prepared.db")], timeout=75)
            report["database_preparation"] = json.loads(preparation.stdout)
            counts = copy_tree(Path(cfg["runtime"]["archive_dir"]), output / "archive")
            report["archive_files"], report["archive_bytes"] = counts
            copy_tree(Path(cfg["runtime"]["compose_file"]).parent, output / "deploy")
            credentials = output / "credentials"
            credentials.mkdir(mode=0o700)
            for name, service, account in (
                ("archive-identity", cfg["runtime"]["archive_keychain_service"], cfg["account"]["email"]),
                ("rspamd-password", cfg["rspamd"]["password_keychain_service"], "controller"),
            ):
                secret = command(["/usr/bin/security", "find-generic-password", "-s", service, "-a", account, "-w"]).stdout.strip()
                if not secret or len(secret) > 4096 or b"\n" in secret or b"\x00" in secret:
                    raise CaptureError("A required recovery credential has an invalid format.")
                write_private(credentials / name, secret + b"\n")
            exported = command([str(recovery), "export-redis", "--config", str(output / "config.toml"),
                                "--output", str(output / "redis.rdb")], env=pauser.env, timeout=75)
            report["model_export"] = json.loads(exported.stdout)
            pauser.assert_quiescent()
            report["captured_utc"] = utc()
            if keep_paused:
                pauser.assert_paused()
                report["mac_paused_utc"] = utc()
                # Publication is still under guardian.lock. Any publication
                # failure takes the normal finally path and resumes the Mac.
                publish_capture(output, report, keep_paused=True)
                leave_paused = True
    except BaseException:
        if keep_paused:
            leave_paused = False
            invalidate_publication(output)
        raise
    finally:
        if not leave_paused:
            pauser.resume()
    if not keep_paused:
        report["mac_resumed_utc"] = utc()
        publish_capture(output, report, keep_paused=False)
    return report


def resume_from_receipt(home, stage):
    """Resume only on an explicit operator assertion that VPS never mutated mail."""
    if sys.platform != "darwin" or stage.resolve() != stage:
        raise CaptureError("Resume requires a real absolute macOS capture path.")
    metadata = stage.stat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
        raise CaptureError("The capture directory must be private and owned by this user.")
    receipt_path = stage / "baseline/pause-receipt.json"
    fd = os.open(receipt_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077
                or metadata.st_nlink != 1 or metadata.st_size > 65536):
            raise CaptureError("The pause receipt must be a private bounded regular file.")
        receipt = json.loads(stream.read(65537))
    if (receipt.get("version") != 1 or receipt.get("uid") != os.getuid()
            or receipt.get("home") != str(home) or set(receipt.get("launchd", {})) != set(LABELS)
            or not isinstance(receipt.get("gui_was_running"), bool) or receipt.get("scanner_was_running") is not True):
        raise CaptureError("The pause receipt does not match this Mac.")
    for previous in receipt["launchd"].values():
        if (set(previous) != {"loaded", "disabled"}
                or not all(isinstance(value, bool) for value in previous.values())):
            raise CaptureError("The pause receipt has invalid service state.")
    if (stage / "PAUSE_RESUMED.json").exists():
        raise CaptureError("This receipt already records a resumed Mac; inspect current state.")
    configuration = home / "Library/Application Support/O2 Mail Guardian/config.toml"
    if hashlib.sha256(configuration.read_bytes()).hexdigest() != receipt.get("source_config_sha256"):
        raise CaptureError("The Mac configuration changed; do not resume this captured owner automatically.")
    pauser = MacPause(home, tomllib.loads(configuration.read_text()), stage / "baseline")
    pauser.original = receipt["launchd"]
    pauser.changed = list(LABELS)
    pauser.scanner_stopped = True
    pauser.gui_was_running = receipt["gui_was_running"]
    pauser.resume()
    atomic_json_private(stage / "PAUSE_RESUMED.json", {
        "version": 1, "resumed_utc": utc(), "operator_asserted_vps_never_mutated": True,
    })


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", action="store_true")
    parser.add_argument("--keep-paused", action="store_true", help="leave Mac disabled after a successful final capture")
    parser.add_argument("--resume-from", type=Path, help="resume from a private pause receipt before any VPS mailbox mutation")
    parser.add_argument("--vps-never-mutated", action="store_true", help="operator asserts VPS is fenced and never changed mail/model")
    parser.add_argument("--recovery", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.resume_from:
        if args.capture or args.keep_paused or args.output or args.recovery or not args.vps_never_mutated:
            parser.error("resume requires only --resume-from CAPTURE_DIR --vps-never-mutated; after server mutation use latest-state failback")
    elif args.vps_never_mutated or (args.keep_paused and not args.capture):
        parser.error("--keep-paused requires --capture; --vps-never-mutated requires --resume-from")
    elif not args.capture:
        print("Preview only: pause Mac Guardian and Rspamd, capture DB/model/archives and recovery keys, then resume Mac. No IMAP password or VPS mailbox work.")
        return
    if args.capture and (not args.recovery or not args.output or not args.recovery.is_absolute() or not args.output.is_absolute()):
        parser.error("--capture requires absolute --recovery and --output paths")
    home = Path.home()
    configuration = home / "Library/Application Support/O2 Mail Guardian/config.toml"
    previous = signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(CaptureError("Capture interrupted.")))
    try:
        if args.resume_from:
            resume_from_receipt(home, args.resume_from)
            print(json.dumps({"mac_resumed": True, "vps_never_mutated": True}))
            return
        result = capture(home, configuration, args.recovery, args.output, keep_paused=args.keep_paused)
        print(json.dumps({"capture_complete": True, "mac_resumed": not args.keep_paused, "mac_paused": args.keep_paused,
                          "archive_files": result["archive_files"], "output": str(args.output)}))
    except CaptureError as error:
        print(str(error) + " Capture incomplete; inspect the private stage and verify Mac restoration before retrying.", file=sys.stderr)
        raise SystemExit(1) from None
    except (OSError, ValueError, sqlite3.Error, KeyboardInterrupt):
        print("Capture incomplete; inspect the private stage and verify Mac restoration before retrying.", file=sys.stderr)
        raise SystemExit(1) from None
    finally:
        signal.signal(signal.SIGTERM, previous)


if __name__ == "__main__":
    main()
