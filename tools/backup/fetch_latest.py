#!/usr/bin/env python3
"""Download only the newest completed encrypted VPS backup over pinned SSH."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import subprocess
import sys
import tempfile
import threading

MAX_BUNDLE = 3 << 30
LABEL = "pl.o2.mail-guardian.backup-pull"

# The remote account already has administrative sudo. This program only reads
# the fixed root-controlled encrypted backup tree; it never handles plaintext.
REMOTE = r'''
import hashlib, json, os, re, stat, sys
from pathlib import Path
root=Path("/var/backups/mail-guardian/__INSTANCE__")
for entry in (root,*root.parents):
    st=entry.lstat()
    if st.st_uid != 0 or st.st_mode & 0o022 or stat.S_ISLNK(st.st_mode):
        raise SystemExit("unsafe backup directory")
rows=sorted(p for p in root.glob("*.age.sha256") if re.fullmatch(r"[0-9]{8}T[0-9]{6}\.[0-9]{6}Z\.age\.sha256",p.name))
if not rows:
    raise SystemExit("no completed encrypted backup")
receipt=rows[-1]
fd=os.open(receipt,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
with os.fdopen(fd,"rb") as f:
    st=os.fstat(f.fileno())
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_nlink != 1 or st.st_size > 200 or st.st_mode & 0o077:
        raise SystemExit("unsafe completion receipt")
    raw=f.read(201).decode("ascii")
name=receipt.name[:-7]
matched=re.fullmatch(r"([0-9a-f]{64})  "+re.escape(name)+r"\n",raw)
if not matched:
    raise SystemExit("invalid completion receipt")
fd=os.open(root/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
with os.fdopen(fd,"rb") as f:
    before=os.fstat(f.fileno())
    if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1 or before.st_mode & 0o077 or not 0 < before.st_size <= 3<<30:
        raise SystemExit("unsafe encrypted backup")
    print(json.dumps({"name":name,"bytes":before.st_size,"sha256":matched[1]}),flush=True)
    remaining=before.st_size
    while remaining:
        block=f.read(min(remaining,65536))
        if not block:
            raise SystemExit("truncated backup")
        sys.stdout.buffer.write(block)
        remaining-=len(block)
    after=os.fstat(f.fileno())
    if f.read(1) or (before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_size,after.st_mtime_ns,after.st_ctime_ns):
        raise SystemExit("backup changed")
sys.stdout.buffer.flush()
'''


def private_directory(path):
    path = Path(path).expanduser().absolute()
    # Refuse existing symlink components, including within the user's home.
    for parent in reversed((path, *path.parents)):
        if parent.is_symlink():
            raise ValueError("backup destination contains a symlink")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("backup destination must be private and owned by the user")
    return path


def metadata(raw):
    row = json.loads(raw)
    if (not isinstance(row, dict) or set(row) != {"name", "bytes", "sha256"} or
            not re.fullmatch(r"[0-9]{8}T[0-9]{6}\.[0-9]{6}Z\.age", row.get("name", "")) or
            not re.fullmatch(r"[0-9a-f]{64}", row.get("sha256", "")) or
            type(row.get("bytes")) is not int or not 0 < row["bytes"] <= MAX_BUNDLE):
        raise ValueError("invalid encrypted backup metadata")
    return row


def receive(stream, target):
    header = stream.readline(4097)
    if len(header) > 4096 or not header.endswith(b"\n"):
        raise ValueError("invalid encrypted backup header")
    row = metadata(header)
    space = os.statvfs(target)
    if space.f_bavail * space.f_frsize < row["bytes"] + (2 << 30):
        raise ValueError("insufficient space for encrypted backup")
    fd, temporary = tempfile.mkstemp(prefix=".encrypted-download-", dir=target)
    try:
        digest = hashlib.sha256()
        with os.fdopen(fd, "wb") as output:
            os.fchmod(output.fileno(), 0o600)
            remaining = row["bytes"]
            while remaining:
                block = stream.read(min(remaining, 64 << 10))
                if not block:
                    raise ValueError("encrypted backup download was truncated")
                output.write(block)
                digest.update(block)
                remaining -= len(block)
            if stream.read(1) or digest.hexdigest() != row["sha256"]:
                raise ValueError("encrypted backup download checksum mismatch")
            output.flush()
            os.fsync(output.fileno())
        return row, Path(temporary)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def publish(row, temporary, target):
    destination = target / row["name"]
    try:
        os.link(temporary, destination)
    except FileExistsError:
        fd = os.open(destination, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as existing:
            info = os.fstat(existing.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                    info.st_mode & 0o077 or info.st_size != row["bytes"] or
                    hashlib.file_digest(existing, "sha256").hexdigest() != row["sha256"]):
                raise ValueError("retained encrypted backup differs; preserving the retained copy")
    finally:
        temporary.unlink(missing_ok=True)
    receipt = target / (row["name"] + ".sha256")
    text = row["sha256"] + "  " + row["name"] + "\n"
    fd, receipt_temporary = tempfile.mkstemp(prefix=".receipt-", dir=target)
    try:
        with os.fdopen(fd, "w") as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(text)
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(receipt_temporary, receipt)
        except FileExistsError:
            existing_fd = os.open(receipt, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(existing_fd, "r") as existing:
                info = os.fstat(existing.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                        info.st_mode & 0o077 or info.st_size > 200 or existing.read(201) != text):
                    raise ValueError("retained encrypted backup receipt differs")
    finally:
        Path(receipt_temporary).unlink(missing_ok=True)
    directory = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    print("Verified encrypted Guardian backup retained: " + row["name"])


def fetch(args):
    target = private_directory(args.destination)
    process = subprocess.Popen(["/usr/bin/ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                                "-o", "ForwardAgent=no", "-o", "UpdateHostKeys=no", "-o", "ConnectTimeout=10",
                                "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=2",
                                args.host, "sudo", "-n", "/usr/bin/python3", "-"],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    deadline = threading.Timer(300, process.kill)
    deadline.daemon = True
    deadline.start()
    temporary = None
    try:
        process.stdin.write(REMOTE.replace("__INSTANCE__", args.instance).encode())
        process.stdin.close()
        row, temporary = receive(process.stdout, target)
        if process.wait(timeout=30) != 0:
            raise ValueError("remote encrypted backup read failed")
        publish(row, temporary, target)
    finally:
        deadline.cancel()
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        if process.poll() is None:
            process.kill()
        process.wait()


def install_agent(args):
    if sys.platform != "darwin":
        raise ValueError("the optional fetch LaunchAgent requires macOS")
    agent_dir = Path.home() / "Library" / "LaunchAgents"
    agent_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    destination = agent_dir / (LABEL + ".plist")
    log_dir = private_directory(Path.home() / ".codex" / "backups" / "o2-guardian" / "backup-pull-logs")
    arguments = [sys.executable, "-I", str(Path(__file__).resolve()), "--host", args.host,
                 "--instance", args.instance, "--destination", str(Path(args.destination).expanduser().absolute())]
    payload = plistlib.dumps({"Label": LABEL, "ProgramArguments": arguments,
                             "RunAtLoad": True, "StartInterval": 3600, "ProcessType": "Background",
                             "StandardOutPath": str(log_dir / "output.log"),
                             "StandardErrorPath": str(log_dir / "error.log")})
    # This explicit installer refuses to overwrite any existing job.
    with destination.open("xb") as output:
        os.chmod(destination, 0o600)
        output.write(payload)
    subprocess.run(["/bin/launchctl", "bootstrap", "gui/" + str(os.getuid()), str(destination)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("Installed hourly encrypted Guardian backup pull.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="vps-1")
    parser.add_argument("--instance", default="pilot")
    parser.add_argument("--destination", default="~/.codex/backups/o2-guardian/vps-1-daily")
    parser.add_argument("--install-agent", action="store_true")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,100}", args.host) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,28}", args.instance):
        raise ValueError("invalid fixed host or instance")
    os.umask(0o077)
    if args.install_agent:
        install_agent(args)
    else:
        fetch(args)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Guardian encrypted backup download failed; check SSH and the backup job.", file=sys.stderr)
        sys.exit(1)
