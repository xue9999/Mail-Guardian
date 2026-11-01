#!/usr/bin/python3
"""Run all three read-only VPS update reviews and aggregate safe summaries.

Exit 0 means no findings, 2 means findings need review, and 1 means at least
one check failed. Failure takes precedence while findings stay visible. This
does not install updates or establish vulnerability exploitability.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time

CHECKS = (
    ("docker", "/usr/local/libexec/vps-docker-security-check", 720),
    ("rspamd", "/usr/local/libexec/vps-rspamd-advisory-check", 210),
    ("unbound", "/usr/local/libexec/vps-unbound-advisory-check", 190),
)
SAFE_ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LC_ALL": "C", "HOME": "/root"}
MAX_OUTPUT = 2 * 1024 * 1024
VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}(?:-[a-z0-9.]+)?\Z")
RELEASE_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
DEB_VERSION = re.compile(r"[A-Za-z0-9.+:~_-]{1,128}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}\Z")
UTC_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|\+00:00)\Z")
PACKAGES = {"docker-ce", "docker-ce-cli", "containerd.io", "docker-buildx-plugin",
            "docker-compose-plugin", "docker-ce-rootless-extras", "docker-model-plugin",
            "docker-scout-plugin"}
REPOS = {"redis", "rspamd/rspamd", "klutchell/unbound"}


class CheckError(Exception):
    """An intentionally non-sensitive check failure."""


def trusted(path):
    """Refuse paths or ancestors that non-root users can replace."""
    file_path = Path(path)
    if not file_path.is_absolute():
        raise CheckError("checker path is not absolute")
    for p in (file_path, *file_path.parents):
        st = p.lstat()
        if st.st_uid != 0 or st.st_mode & 0o022 or stat.S_ISLNK(st.st_mode):
            raise CheckError("checker path is not root controlled")
        if p == file_path and (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1):
            raise CheckError("checker is not a single-link regular file")
        if p != file_path and not stat.S_ISDIR(st.st_mode):
            raise CheckError("checker ancestor is not a directory")


def run_bounded(path, timeout):
    """Read bounded stdout only; never forward stderr or raw child output."""
    p = subprocess.Popen(["/usr/bin/python3", "-I", str(path)], env=SAFE_ENV,
                         stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, start_new_session=True)
    deadline = time.monotonic() + timeout
    output = bytearray()
    complete = False
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(p.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise CheckError("check timed out")
                block = os.read(p.stdout.fileno(), 65536)
                if not block:
                    break
                output.extend(block)
                if len(output) > MAX_OUTPUT:
                    raise CheckError("check output exceeded limit")
        try:
            rc = p.wait(timeout=max(0.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as exc:
            raise CheckError("check timed out") from exc
        try:
            result = json.loads(output)
        except (ValueError, UnicodeDecodeError, RecursionError) as exc:
            raise CheckError("check returned invalid JSON") from exc
        complete = True
        return rc, result
    finally:
        if not complete:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if p.poll() is None:
            p.kill()
            try:
                p.wait(timeout=2)
            except subprocess.TimeoutExpired:
                # The surrounding systemd unit kills the complete cgroup.
                pass
        p.stdout.close()


def list_value(data, key, max_items=200):
    value = data.get(key)
    if not isinstance(value, list) or len(value) > max_items:
        raise CheckError("invalid check report")
    return value


def version(value, pattern=VERSION, *, nullable=False):
    if value is None and nullable:
        return None
    if not isinstance(value, str) or len(value) > 128 or not pattern.fullmatch(value):
        raise CheckError("invalid check report")
    return value


def docker_summary(data):
    packages = []
    seen_packages = set()
    for item in list_value(data, "packages", 32):
        if (not isinstance(item, dict) or item.get("name") not in PACKAGES or
                item["name"] in seen_packages or type(item.get("update_available")) is not bool):
            raise CheckError("invalid Docker package report")
        seen_packages.add(item["name"])
        packages.append({"name": item["name"], "installed": version(item.get("installed"), DEB_VERSION),
                         "candidate": version(item.get("candidate"), DEB_VERSION),
                         "update_available": item["update_available"]})
    patches = []
    for item in list_value(data, "patch_candidates", 16):
        if not isinstance(item, dict) or item.get("repo") not in REPOS:
            raise CheckError("invalid image candidate report")
        choice = item.get("candidate")
        row = {"repo": item["repo"], "installed_tag": version(item.get("installed_tag")), "candidate": None}
        if choice is not None:
            if not isinstance(choice, dict):
                raise CheckError("invalid image candidate report")
            row["candidate"] = {"tag": version(choice.get("tag")), "digest": version(choice.get("digest"), DIGEST)}
        patches.append(row)
    image_changes = []
    images = list_value(data, "images", 16)
    seen_tags = set()
    for item in images:
        if not isinstance(item, dict) or type(item.get("digest_changed")) is not bool:
            raise CheckError("invalid image digest report")
        tag = item.get("tag")
        if not isinstance(tag, str) or ":" not in tag:
            raise CheckError("invalid image digest report")
        repo, image_tag = tag.rsplit(":", 1)
        if repo not in REPOS or repo in seen_tags:
            raise CheckError("invalid image digest report")
        seen_tags.add(repo)
        version(image_tag)
        previous = version(item.get("pinned_digest"), DIGEST)
        current = version(item.get("tag_digest"), DIGEST)
        if item["digest_changed"] != (previous != current):
            raise CheckError("inconsistent image digest report")
        if item["digest_changed"]:
            image_changes.append({"repo": repo, "tag": image_tag, "digest": current})
    consistency = {}
    for key in ("compose_matches_release", "rspamd_helper_matches_compose", "runtime_images_match_compose"):
        value = data.get(key)
        if value is not None and type(value) is not bool:
            raise CheckError("invalid configuration report")
        consistency[key] = value
    if not data["errors"]:
        if (not packages or {p["repo"] for p in patches} != REPOS or len(patches) != len(REPOS)
                or seen_tags != REPOS or not all(consistency.values())):
            raise CheckError("incomplete Docker report")
        derived = (any(p["update_available"] for p in packages) or
                   any(p["candidate"] is not None for p in patches) or bool(image_changes))
        if data["attention"] != derived:
            raise CheckError("inconsistent Docker attention")
    return {"packages": packages, "patch_candidates": patches, "image_digest_changes": image_changes,
            "configuration": consistency}


def rspamd_summary(data):
    installed = version(data.get("installed_version"), RELEASE_VERSION, nullable=True)
    entries = []
    seen = set()
    for item in list_value(data, "newer_release_lines", 100):
        if not isinstance(item, dict) or type(item.get("security_language_present")) is not bool:
            raise CheckError("invalid Rspamd release report")
        found = version(item.get("version"), RELEASE_VERSION)
        if found in seen:
            raise CheckError("duplicate Rspamd release")
        seen.add(found)
        if installed is not None and tuple(map(int, found.split(".")))[:2] <= tuple(map(int, installed.split(".")))[:2]:
            raise CheckError("invalid Rspamd release line")
        entries.append({"version": found,
                        "security_language_present": item["security_language_present"]})
    if not data["errors"] and (installed is None or data["attention"] != bool(entries)):
        raise CheckError("inconsistent Rspamd report")
    return {"installed": installed, "newer_release_lines": entries,
            "source": "https://docs.rspamd.com/changelog/"}


def unbound_summary(data):
    installed = version(data.get("installed"), RELEASE_VERSION, nullable=True)
    upstream = version(data.get("upstream_current"), RELEASE_VERSION, nullable=True)
    newer = data.get("newer_upstream")
    if type(newer) is not bool:
        raise CheckError("invalid Unbound release report")
    advisories = []
    for item in list_value(data, "version_range_advisories", 200):
        if not isinstance(item, dict):
            raise CheckError("invalid Unbound advisory report")
        advisories.append(version(item.get("cve"), CVE))
    if not data["errors"]:
        if installed is None or upstream is None:
            raise CheckError("incomplete Unbound report")
        if newer != (tuple(map(int, upstream.split("."))) > tuple(map(int, installed.split(".")))):
            raise CheckError("inconsistent Unbound version comparison")
        if data["attention"] != (newer or bool(advisories)):
            raise CheckError("inconsistent Unbound report")
    return {"installed": installed, "upstream_current": upstream,
            "newer_upstream": newer, "version_range_advisories": advisories,
            "source": "https://www.nlnetlabs.nl/projects/unbound/security-advisories/"}


def summarize(name, rc, result):
    if (not isinstance(result, dict) or type(result.get("attention")) is not bool or
            not isinstance(result.get("errors"), list) or
            not all(isinstance(e, str) for e in result["errors"]) or len(result["errors"]) > 200):
        raise CheckError("check returned an invalid report")
    expected = 1 if result["errors"] else 2 if result["attention"] else 0
    if rc != expected:
        raise CheckError("check exited inconsistently")
    if name == "rspamd" and result.get("mode") != "release_review_only":
        raise CheckError("unexpected Rspamd report mode")
    if name == "unbound" and result.get("mode") != "advisory_only":
        raise CheckError("unexpected Unbound report mode")
    checked_at = result.get("checked_at_utc")
    if not isinstance(checked_at, str) or not UTC_TIME.fullmatch(checked_at):
        raise CheckError("invalid check timestamp")
    try:
        datetime.fromisoformat(checked_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CheckError("invalid check timestamp") from exc
    summaries = {"docker": docker_summary, "rspamd": rspamd_summary, "unbound": unbound_summary}
    return {"checked_at_utc": checked_at, "attention": result["attention"], "error_count": len(result["errors"]),
            "findings": summaries[name](result)}


def review():
    report = {"checked_at_utc": datetime.now(timezone.utc).isoformat(),
              "mode": "aggregate_review_only", "checks": {}, "attention": False,
              "errors": [], "limitations": [
                  "Discovery signals require security and compatibility review; no updates are installed.",
                  "Findings do not prove exploitability, image provenance, container health or complete advisory coverage.",
                  "Child errors and stderr are suppressed; run the affected checker separately for diagnosis."]}
    for name, path, timeout in CHECKS:
        try:
            trusted(path)
            rc, output = run_bounded(path, timeout)
            summary = summarize(name, rc, output)
            report["checks"][name] = summary
            report["attention"] |= summary["attention"]
            if summary["error_count"]:
                report["errors"].append(name + " check reported errors")
        except (CheckError, OSError, subprocess.SubprocessError):
            # Do not echo exception messages, child stderr, untrusted output or paths.
            report["checks"][name] = {"attention": None, "error_count": None, "findings": None}
            report["errors"].append(name + " check failed or returned an invalid report")
    return report


def main():
    report = review()
    print(json.dumps(report, sort_keys=True, indent=2))
    return 1 if report["errors"] else 2 if report["attention"] else 0


if __name__ == "__main__":
    sys.exit(main())
