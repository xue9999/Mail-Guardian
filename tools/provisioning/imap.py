#!/usr/bin/env python3
"""Create the separate VPS IMAP credential using hidden local input and pinned SSH.

Preview is the default. Run --provision yourself in a real Terminal after
creating a separate IMAP account/app password for Guardian VPS-1. No service is started.
"""

import argparse
import getpass
import importlib.util
import os
from pathlib import Path
import sys
import unicodedata
import warnings


_spec = importlib.util.spec_from_file_location(
    "guardian_provision_transport", Path(__file__).with_name("healthchecks.py"))
transport = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(transport)
ProvisionError = transport.ProvisionError
TARGET = transport.TARGET
CREDENTIAL = "/etc/mail-guardian/pilot/credentials/imap-password"
MAX_SECRET = 1024


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise ProvisionError("Use only --provision; enter the password at its hidden prompt.")


def validate_password(text):
    try:
        if (not isinstance(text, str) or not 1 <= len(text.encode("utf-8")) <= MAX_SECRET
                or any(unicodedata.category(char).startswith("C") for char in text)):
            raise ValueError()
        return text
    except (ValueError, UnicodeError, AttributeError):
        raise ProvisionError("The password must contain 1–1024 UTF-8 bytes without control characters.") from None


# Reuse the same descriptor-relative, nofollow, exclusive atomic publication as
# Healthchecks. Only the fixed credential name, validation and input bound differ.
_input_start = transport.REMOTE_PROGRAM.index("def validate_input(raw):")
_input_end = transport.REMOTE_PROGRAM.index("def open_directory(", _input_start)
_password_input = r'''
def validate_input(raw):
    import unicodedata
    if not isinstance(raw, bytes) or not 2 <= len(raw) <= 1025 or not raw.endswith(b"\n"):
        raise ValueError("invalid credential input")
    text = raw[:-1].decode("utf-8", "strict")
    if not text or any(unicodedata.category(char).startswith("C") for char in text):
        raise ValueError("invalid credential input")
    return text.encode("utf-8") + b"\n"

'''
REMOTE_PROGRAM = (
    transport.REMOTE_PROGRAM[:_input_start] + _password_input
    + transport.REMOTE_PROGRAM[_input_end:]
).replace('NAME = "healthchecks-url"', 'NAME = "imap-password"').replace(
    '".healthchecks-url-"', '".imap-password-"').replace(
    "sys.stdin.buffer.read(257)", "sys.stdin.buffer.read(1026)")


def ssh_command():
    return transport.ssh_command(REMOTE_PROGRAM)


def prompt_password():
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise ProvisionError("Run --provision in a real Terminal; redirected input is refused.")
    try:
        tty = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY | os.O_CLOEXEC)
        try:
            if not os.isatty(tty):
                raise ProvisionError("A controlling Terminal is required.")
        finally:
            os.close(tty)
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            first = validate_password(getpass.getpass("New Guardian VPS-1 IMAP password (hidden): "))
            second = validate_password(getpass.getpass("Repeat the VPS app password (hidden): "))
        if first != second:
            raise ProvisionError("The two passwords differ; nothing was provisioned.")
        return first
    except (OSError, EOFError, KeyboardInterrupt, getpass.GetPassWarning):
        raise ProvisionError("A working no-echo Terminal is required; nothing was provisioned.") from None


def send_secret(password, *, _command=None, _timeout=transport.TIMEOUT):
    payload = (validate_password(password) + "\n").encode("utf-8")
    return transport.send_payload(payload,
                                  _command=ssh_command() if _command is None else _command,
                                  _timeout=_timeout)


def main(argv=None):
    parser = SafeArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--provision", action="store_true",
                        help="enter the separate VPS app password twice, then create its credential")
    try:
        args = parser.parse_args(argv)
        if not args.provision:
            print("Prepared operation:", TARGET, CREDENTIAL)
            print("Run --provision in Terminal to enter the new VPS app password twice without echo.")
            print("Existing credentials are never replaced; no service is started.")
            return 0
        send_secret(prompt_password())
    except ProvisionError as error:
        print(str(error), file=sys.stderr)
        return 1
    print("VPS IMAP credential created privately. The worker and schedule remain unchanged.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
