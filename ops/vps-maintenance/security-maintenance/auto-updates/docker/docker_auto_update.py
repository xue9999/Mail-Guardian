#!/usr/bin/env python3
"""Candidate Docker update policy; execution is intentionally not implemented.

The user's policy permits stable patch releases on the same major/minor line.
This module is *not* an automatic updater. Do not install it on the host or
schedule it until guarded execution, durable fencing and recovery are built
and tested end to end.
"""

import re
import subprocess


VERSION = re.compile(
    r"^(?:(?P<epoch>\d+):)?(?P<major>\d+)\.(?P<minor>\d+)\."
    r"(?P<patch>\d+)(?:-(?P<revision>[0-9][A-Za-z0-9.+~]*))?$"
)
PRERELEASE = re.compile(r"(?:~|[.+-])(?:rc|alpha|beta|dev|pre)(?:[0-9.+~-]|$)", re.I)


def version_is_newer(installed: str, candidate: str) -> bool:
    result = subprocess.run(
        ["dpkg", "--compare-versions", candidate, "gt", installed],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
    )
    if result.returncode not in (0, 1):
        raise RuntimeError("dpkg version comparison failed")
    return result.returncode == 0


def patch_update_allowed(installed: str, candidate: str) -> bool:
    old = VERSION.fullmatch(installed)
    new = VERSION.fullmatch(candidate)
    if old is None or new is None or PRERELEASE.search(candidate):
        return False
    if (old.group("epoch") or "0", old.group("major"), old.group("minor")) != (
        new.group("epoch") or "0", new.group("major"), new.group("minor")
    ):
        return False
    return version_is_newer(installed, candidate)


INSTALL = re.compile(
    r"^Inst\s+(?P<name>\S+)\s+\[(?P<old>[^\]]+)\]\s+"
    r"\((?P<version>\S+)\s+(?P<origin>Docker(?: CE)?:resolute)(?:\s+[^)]*)?\)$"
)
CONFIGURE = re.compile(r"^Conf\s+(?P<name>\S+)\s+\((?P<version>\S+)\s+(?P<origin>Docker(?: CE)?:resolute)(?:\s+[^)]*)?\)$")


def simulation_is_safe(output: str, expected: dict[str, str]) -> bool:
    """Only accept an exact existing-package, Docker-origin APT transaction."""
    if not expected:
        return False
    observed: dict[str, str] = {}
    configured: dict[str, str] = {}
    for line in output.splitlines():
        line = line.strip()
        action = line.split(None, 1)[0] if line else ""
        if action in ("Remv", "Purg"):
            return False
        if action == "Conf":
            match = CONFIGURE.fullmatch(line)
            if (match is None or match.group("name") not in expected or
                    expected[match.group("name")] != match.group("version") or
                    match.group("origin") not in ("Docker:resolute", "Docker CE:resolute") or
                    match.group("name") in configured):
                return False
            configured[match.group("name")] = match.group("version")
            continue
        if action != "Inst":
            continue
        match = INSTALL.fullmatch(line)
        if match is None:
            return False
        name, version = match.group("name"), match.group("version")
        if name in observed or name not in expected or expected[name] != version:
            return False
        if match.group("origin") not in ("Docker:resolute", "Docker CE:resolute"):
            return False
        observed[name] = version
    return observed == expected and configured == expected


if __name__ == "__main__":
    raise SystemExit("Policy candidate only: automatic package installation is not implemented")
