#!/usr/bin/env python3
"""Provision one hidden Healthchecks URL through the existing pinned vps-1 SSH alias.

This helper does not install/start a service, ping Healthchecks, or read mail.
It refuses an existing credential. Run --provision from a real Terminal only.
"""

import argparse
import getpass
import os
from pathlib import Path
import selectors
import shlex
import signal
import subprocess
import sys
import time
import urllib.parse
import uuid
import warnings

TARGET = "vps-1"
CREDENTIAL = "/etc/mail-guardian/pilot/credentials/healthchecks-url"
MAX_SECRET = 256
MAX_RESPONSE = 1024
TIMEOUT = 30


class ProvisionError(Exception):
    """Only fixed, nonsecret messages may leave this helper."""


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's default error includes unrecognized values. A user who
        # accidentally puts the bearer URL in argv must not see it echoed.
        raise ProvisionError("Use only --provision; enter the URL at its hidden prompt.")


def validate_url(text):
    try:
        if not isinstance(text, str) or not 0 < len(text) < MAX_SECRET:
            raise ValueError()
        text.encode("ascii", "strict")
        parsed = urllib.parse.urlsplit(text)
        token = parsed.path[1:]
        canonical = "https://hc-ping.com/" + str(uuid.UUID(token))
        if (text != canonical or parsed.scheme != "https" or
                parsed.netloc != "hc-ping.com" or parsed.query or parsed.fragment):
            raise ValueError()
        return canonical
    except (ValueError, UnicodeError, AttributeError):
        raise ProvisionError("The URL is not a canonical Healthchecks UUID ping URL.") from None


# The command and destination are fixed. Secret input is read only from stdin;
# there is no remote argument, environment variable, or general write interface.
# Functions accept fixture paths/owners solely for isolated local unit tests;
# the remotely executed main always selects the literal production destination.
REMOTE_PROGRAM = r'''
import os
import secrets
import stat
import sys
import urllib.parse
import uuid

DIRECTORY = "/etc/mail-guardian/pilot/credentials"
NAME = "healthchecks-url"

def validate_input(raw):
    if not isinstance(raw, bytes) or len(raw) > 256 or not raw.endswith(b"\n"):
        raise ValueError("invalid credential input")
    text = raw[:-1].decode("ascii", "strict")
    parsed = urllib.parse.urlsplit(text)
    token = parsed.path[1:]
    canonical = "https://hc-ping.com/" + str(uuid.UUID(token))
    if (text != canonical or parsed.scheme != "https" or parsed.netloc != "hc-ping.com"
            or parsed.query or parsed.fragment):
        raise ValueError("invalid credential input")
    return canonical.encode("ascii") + b"\n"

def open_directory(path, owner=0):
    if not path.startswith("/") or os.path.normpath(path) != path or path == "/":
        raise ValueError("unsafe credential directory")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.split("/")[1:]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                          dir_fd=fd)
            os.close(fd)
            fd = nxt
            info = os.fstat(fd)
            if info.st_uid not in (0, owner) or info.st_mode & 0o022:
                raise ValueError("unsafe credential directory")
        info = os.fstat(fd)
        if info.st_uid != owner or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("unsafe credential directory")
        return fd
    except BaseException:
        os.close(fd)
        raise

def same_file(a, b):
    return (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino)

def publish_secret(raw, directory=DIRECTORY, owner=0):
    payload = validate_input(raw)
    if os.geteuid() != owner:
        raise ValueError("wrong credential owner")
    directory_fd = open_directory(directory, owner)
    fd = None
    temporary = None
    created = None
    try:
        try:
            os.stat(NAME, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError("credential already exists")
        temporary = ".healthchecks-url-" + secrets.token_hex(16)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                     os.O_CLOEXEC | os.O_NONBLOCK, 0o600, dir_fd=directory_fd)
        os.fchmod(fd, 0o600)
        created = os.fstat(fd)
        position = 0
        while position < len(payload):
            written = os.write(fd, payload[position:])
            if written <= 0:
                raise OSError("credential write failed")
            position += written
        os.fsync(fd)
        # Refuse a substituted directory before publication. Descriptor-relative
        # operations cannot be redirected into a user-selected replacement tree.
        fresh = open_directory(directory, owner)
        try:
            if not same_file(os.fstat(directory_fd), os.fstat(fresh)):
                raise ValueError("credential directory changed")
        finally:
            os.close(fresh)
        os.link(temporary, NAME, src_dir_fd=directory_fd, dst_dir_fd=directory_fd,
                follow_symlinks=False)
        # Never remove NAME after publication: a sync failure is indeterminate
        # and must be inspected. Existing credentials are never overwritten.
        os.fsync(directory_fd)
        os.unlink(temporary, dir_fd=directory_fd)
        temporary = None
        os.fsync(directory_fd)
        final = os.stat(NAME, dir_fd=directory_fd, follow_symlinks=False)
        if (not same_file(created, final) or not stat.S_ISREG(final.st_mode) or
                final.st_uid != owner or stat.S_IMODE(final.st_mode) != 0o600 or
                final.st_nlink != 1 or final.st_size != len(payload)):
            raise ValueError("credential publication did not verify")
    finally:
        if temporary is not None and created is not None:
            try:
                current = os.stat(temporary, dir_fd=directory_fd, follow_symlinks=False)
                if same_file(created, current):
                    os.unlink(temporary, dir_fd=directory_fd)
                    os.fsync(directory_fd)
            except OSError:
                pass
        if fd is not None:
            os.close(fd)
        os.close(directory_fd)

if __name__ == "__main__":
    try:
        if os.geteuid() != 0:
            raise ValueError("root is required")
        os.umask(0o077)
        publish_secret(sys.stdin.buffer.read(257))
    except BaseException:
        sys.stderr.write("credential-provisioning-failed\n")
        sys.exit(1)
    sys.stdout.write("credential-created\n")
'''


def ssh_command(remote_program=REMOTE_PROGRAM):
    remote = "sudo -n /usr/bin/python3 -I -c " + shlex.quote(remote_program)
    return ["/usr/bin/ssh", "-T", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
            "-o", "IdentityAgent=none", "-o", "StrictHostKeyChecking=yes",
            "-o", "UpdateHostKeys=no", "-o", "VerifyHostKeyDNS=no",
            "-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no",
            "-o", "ForwardX11=no", "-o", "PermitLocalCommand=no",
            "-o", "ProxyCommand=none", "-o", "ProxyJump=none",
            "-o", "ControlMaster=no", "-o", "ControlPath=none",
            "-o", "ConnectionAttempts=1", "-o", "ConnectTimeout=10",
            "-o", "LogLevel=ERROR", TARGET, remote]


def prompt_url():
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise ProvisionError("Run --provision in a real Terminal; redirected input is refused.")
    try:
        tty = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY | os.O_CLOEXEC)
        try:
            if not os.isatty(tty):
                raise ProvisionError("A controlling Terminal is required.")
        finally:
            os.close(tty)
        # A getpass fallback can echo input. Turn its warning into a failure
        # before that fallback reads anything; never accept echoed credentials.
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            return validate_url(getpass.getpass("Healthchecks ping URL (hidden): "))
    except (OSError, EOFError, KeyboardInterrupt, getpass.GetPassWarning):
        raise ProvisionError("A working no-echo Terminal is required; nothing was provisioned.") from None


def send_secret(url, *, _command=None, _timeout=TIMEOUT):
    payload = (validate_url(url) + "\n").encode("ascii")
    return send_payload(payload, _command=_command, _timeout=_timeout)


def send_payload(payload, *, _command=None, _timeout=TIMEOUT):
    """Bounded credential transport; callers must validate their fixed payload."""
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= 1025:
        raise ProvisionError("Invalid credential payload.")
    command = ssh_command() if _command is None else _command
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(Path.home()),
                   "LANG": "C", "LC_ALL": "C"}
    proc = None
    try:
        proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=environment,
                                close_fds=True, start_new_session=True)
        # Payload is at most 1025 bytes, below a pipe's atomic write size.
        # It appears in neither argv nor the SSH environment.
        proc.stdin.write(payload)
        proc.stdin.close()
        buffers = {proc.stdout: bytearray(), proc.stderr: bytearray()}
        deadline = time.monotonic() + _timeout
        with selectors.DefaultSelector() as selector:
            for stream in buffers:
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ProvisionError("Provisioning status is uncertain; inspect before retrying.")
                for key, _ in selector.select(min(remaining, 0.1)):
                    chunk = os.read(key.fileobj.fileno(), MAX_RESPONSE + 1)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    buffers[key.fileobj].extend(chunk)
                    if len(buffers[key.fileobj]) > MAX_RESPONSE:
                        raise ProvisionError("Provisioning status is uncertain; inspect before retrying.")
            remaining = deadline - time.monotonic()
            if remaining <= 0 or proc.wait(timeout=remaining) != 0:
                raise ProvisionError("Provisioning did not complete; inspect before retrying.")
        if bytes(buffers[proc.stdout]) != b"credential-created\n" or buffers[proc.stderr]:
            raise ProvisionError("Provisioning status is uncertain; inspect before retrying.")
    except ProvisionError:
        raise
    except (OSError, subprocess.SubprocessError):
        raise ProvisionError("Provisioning did not complete; inspect before retrying.") from None
    finally:
        if proc is not None:
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait()
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                if stream is not None and not stream.closed:
                    stream.close()


def main(argv=None):
    parser = SafeArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--provision", action="store_true",
                        help="prompt without echo, then create the one fixed remote credential")
    try:
        args = parser.parse_args(argv)
    except ProvisionError as error:
        print(str(error), file=sys.stderr)
        return 1
    if not args.provision:
        print("Prepared operation:", TARGET, CREDENTIAL)
        print("Run --provision in Terminal to enter a hidden URL. Existing files are never replaced.")
        return 0
    try:
        url = prompt_url()
        send_secret(url)
    except ProvisionError as error:
        print(str(error), file=sys.stderr)
        return 1
    print("Healthchecks credential created on vps-1. No service was installed or enabled; no ping was sent.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
