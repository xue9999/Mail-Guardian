#!/usr/bin/env python3
"""Discover same-minor Guardian image candidates; never deploy or change state."""

import argparse
import datetime
import json
from pathlib import Path
import re
import sys
import urllib.parse
import urllib.request

REPOSITORIES = {
    "redis": ("library/redis", "-alpine"),
    "rspamd/rspamd": ("rspamd/rspamd", ""),
    "klutchell/unbound": ("klutchell/unbound", ""),
}
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
PIN = re.compile(r"([^:@\s]+):(\d+)\.(\d+)\.(\d+)(-[a-z0-9.]+)?@(sha256:[0-9a-f]{64})\Z")
IMAGE_LINE = re.compile(r"^\s*image:\s*([^\s#]+)\s*(?:#.*)?$")
HUB = "hub.docker.com"


def parse_pin(ref):
    if not isinstance(ref, str):
        raise TypeError("image reference must be a string")
    match = PIN.fullmatch(ref)
    if not match:
        raise ValueError("image reference is not a strict version and digest pin")
    repo, major, minor, patch, suffix, digest = match.groups()
    suffix = suffix or ""
    if repo not in REPOSITORIES or suffix != REPOSITORIES[repo][1]:
        raise ValueError("repository or variant is outside the supported allowlist")
    if any(str(int(x)) != x for x in (major, minor, patch)):
        raise ValueError("version has noncanonical numeric components")
    return {"repo": repo, "hub_repo": REPOSITORIES[repo][0],
            "tag": f"{major}.{minor}.{patch}{suffix}", "digest": digest,
            "major": int(major), "minor": int(minor), "patch": int(patch),
            "suffix": suffix}


def select_patch(pin, rows):
    version = re.compile(rf"{pin['major']}\.{pin['minor']}\.(0|[1-9][0-9]*){re.escape(pin['suffix'])}\Z")
    candidates, seen = [], {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        name, digest = row.get("name"), row.get("digest")
        if not isinstance(name, str):
            continue
        match = version.fullmatch(name)
        if not match:
            continue
        if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
            raise ValueError("matching version has an invalid digest")
        if name in seen and seen[name] != digest:
            raise ValueError("same tag has conflicting registry digests")
        seen[name] = digest
        patch = int(match.group(1))
        if patch < pin["patch"] or (patch == pin["patch"] and digest == pin["digest"]):
            continue
        candidates.append((patch, row))
    return max(candidates, key=lambda item: item[0])[1] if candidates else None


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def validate_url(url, expected_path=None):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname != HUB or parsed.port not in (None, 443)
            or parsed.username or parsed.password or parsed.fragment
            or not parsed.path.startswith("/v2/repositories/")):
        raise ValueError("unexpected registry URL")
    if expected_path is not None and parsed.path.rstrip("/") != expected_path.rstrip("/"):
        raise ValueError("pagination left the expected repository")


def tags_for(pin):
    path = "/v2/repositories/" + pin["hub_repo"] + "/tags"
    expected_name = f"{pin['major']}.{pin['minor']}."
    query = urllib.parse.urlencode({"name": expected_name, "page_size": 100})
    url = "https://" + HUB + path + "?" + query
    opener = urllib.request.build_opener(SafeRedirect())
    rows, visited, seen_names, expected_count = [], set(), set(), None
    for _ in range(20):
        validate_url(url, path)
        if urllib.parse.parse_qs(urllib.parse.urlsplit(url).query, keep_blank_values=True).get("name") != [expected_name]:
            raise ValueError("registry page does not retain the expected tag filter")
        if url in visited:
            raise ValueError("repeated registry page")
        visited.add(url)
        req = urllib.request.Request(url, headers={"User-Agent": "VPS1GuardianPatchReview/1.0", "Accept": "application/json"})
        with opener.open(req, timeout=20) as response:
            validate_url(response.geturl(), path)
            if urllib.parse.parse_qs(urllib.parse.urlsplit(response.geturl()).query, keep_blank_values=True).get("name") != [expected_name]:
                raise ValueError("registry response did not retain the expected tag filter")
            raw = response.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError("registry response too large")
        data = json.loads(raw)
        if (not isinstance(data, dict) or not isinstance(data.get("results"), list)
                or type(data.get("count")) is not int or data["count"] < 0):
            raise ValueError("unexpected registry response")
        if expected_count is None:
            expected_count = data["count"]
        elif expected_count != data["count"]:
            raise ValueError("registry page count changed during enumeration")
        for row in data["results"]:
            if not isinstance(row, dict) or not isinstance(row.get("name"), str) or not row["name"]:
                raise ValueError("registry page contains a malformed tag")
            if row["name"] in seen_names:
                raise ValueError("registry enumeration repeated a tag")
            seen_names.add(row["name"])
        rows.extend(data["results"])
        url = data.get("next")
        if url is None:
            if len(rows) != expected_count:
                raise ValueError("registry enumeration was incomplete")
            if not any(isinstance(row, dict) and row.get("name") == pin["tag"] for row in rows):
                raise ValueError("installed version tag was not returned by registry")
            return rows
        if not isinstance(url, str):
            raise ValueError("invalid next-page URL")
    raise ValueError("registry pagination exceeded 20 pages")


def image_pins(path):
    refs = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        match = IMAGE_LINE.fullmatch(line)
        if match:
            refs.append(parse_pin(match.group(1).strip("\"'")))
    if len(refs) != 3 or {p["repo"] for p in refs} != set(REPOSITORIES):
        raise ValueError("expected exactly the three allowlisted Guardian images")
    return refs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose", default="/etc/mail-guardian/pilot/deploy/compose.yaml")
    args = parser.parse_args()
    report = {"checked_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "mode": "discovery_only", "images": [], "errors": [],
              "limitations": ["A newer tag or digest is not proof of a security fix or compatibility.",
                              "No images are pulled or deployed, no compatibility test is run, and no services or data are changed.",
                              "The Guardian app has no supported authenticated automatic release channel."]}
    try:
        pins = image_pins(args.compose)
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        report["errors"].append("compose: " + str(exc))
        pins = []
    for pin in pins:
        try:
            rows = tags_for(pin)
            choice = select_patch(pin, rows)
            image = {"repo": pin["repo"], "installed_tag": pin["tag"], "installed_digest": pin["digest"],
                     "candidate": None}
            if choice:
                platforms = choice.get("images")
                if not isinstance(platforms, list) or not any(
                    isinstance(x, dict) and x.get("os") == "linux" and x.get("architecture") == "amd64"
                    and isinstance(x.get("digest"), str) and DIGEST.fullmatch(x["digest"]) for x in platforms
                ):
                    raise ValueError("Docker Hub does not report a linux/amd64 candidate manifest")
                image["candidate"] = {"tag": choice["name"], "digest": choice["digest"]}
            report["images"].append(image)
        except Exception as exc:
            report["errors"].append(pin["repo"] + ": " + type(exc).__name__ + ": " + str(exc)[:300])
    report["attention"] = any(i["candidate"] for i in report["images"])
    print(json.dumps(report, sort_keys=True, indent=2))
    return 1 if report["errors"] else 2 if report["attention"] else 0


if __name__ == "__main__":
    sys.exit(main())
