#!/usr/bin/python3 -I
"""Read-only Ubuntu release discovery; never installs or forces an upgrade.

The final server image catalog establishes publication, while meta-release
separately establishes the ordinary release-upgrader offering. HTTPS catalog
checks do not authenticate an installation image or qualify Guardian runtime.
"""

import argparse
from datetime import datetime, timezone
import hashlib
from http.client import HTTPException
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

RELEASE_ROOT = "https://releases.ubuntu.com/"
NORMAL_FEED = "https://changelogs.ubuntu.com/meta-release"
ALLOWED_HOSTS = frozenset(("releases.ubuntu.com", "changelogs.ubuntu.com"))
MAX_BYTES = 2 << 20
MAX_SECONDS = 60
MAX_CATALOGS = 8
VERSION = re.compile(r"^(\d{1,2})\.(\d{2})(?:\.(\d+))?$")


class CheckError(Exception):
    pass


def version(value):
    match = VERSION.fullmatch(value)
    if not match:
        raise CheckError("Unrecognized Ubuntu version metadata.")
    return tuple(int(part or 0) for part in match.groups())


def valid_url(url):
    try:
        p = urlsplit(url)
        return (p.scheme == "https" and p.hostname in ALLOWED_HOSTS and
                p.port in (None, 443) and not p.username and not p.password and
                not p.query and not p.fragment)
    except ValueError:
        return False


class OfficialRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not valid_url(newurl):
            raise CheckError("Official metadata redirected outside the HTTPS allowlist.")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Fetcher:
    def __init__(self):
        self.deadline = time.monotonic() + MAX_SECONDS
        self.opener = build_opener(OfficialRedirects())
        self.evidence = []

    def __call__(self, url):
        if not valid_url(url):
            raise CheckError("Metadata URL is outside the official HTTPS allowlist.")
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise CheckError("Official metadata check exceeded its deadline.")
        request = Request(url, headers={"User-Agent": "VPS-1-Ubuntu-release-check/1"})
        try:
            with self.opener.open(request, timeout=min(15, remaining)) as response:
                if not valid_url(response.url):
                    raise CheckError("Unexpected metadata response origin.")
                declared_length = response.headers.get("Content-Length")
                if declared_length is not None:
                    if not re.fullmatch(r"[0-9]+", declared_length.strip()):
                        raise CheckError("Official metadata has an invalid declared length.")
                    declared_length = int(declared_length)
                    if declared_length > MAX_BYTES:
                        raise CheckError("Official metadata exceeded its size limit.")
                chunks, count = [], 0
                while True:
                    if time.monotonic() > self.deadline:
                        raise CheckError("Official metadata check exceeded its deadline.")
                    chunk = response.read1(min(65536, MAX_BYTES + 1 - count))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    count += len(chunk)
                    if count > MAX_BYTES:
                        raise CheckError("Official metadata exceeded its size limit.")
                # HTTPResponse.read1() can return EOF without raising
                # IncompleteRead, leaving .length positive. A valid prefix
                # must never be accepted as the complete official catalog.
                if declared_length is not None and count != declared_length:
                    raise CheckError("Official metadata ended before its declared length.")
                data = b"".join(chunks)
                result = data.decode("utf-8", "strict")
        except (HTTPError, URLError, HTTPException, TimeoutError, OSError, UnicodeError, ValueError):
            raise CheckError("Official HTTPS metadata could not be retrieved or decoded.") from None
        self.evidence.append({"url": url, "bytes": len(data),
                              "sha256": hashlib.sha256(data).hexdigest()})
        return result


class Catalog(HTMLParser):
    def __init__(self):
        super().__init__()
        self.versions = set()

    def handle_starttag(self, tag, attrs):
        if tag != "a":
            return
        for key, value in attrs:
            if key == "href" and value and re.fullmatch(r"\d{1,2}\.\d{2}(?:\.\d+)?/", value):
                self.versions.add(value[:-1])


def released_versions(html):
    catalog = Catalog()
    catalog.feed(html)
    if not catalog.versions:
        raise CheckError("Official release catalog contains no recognized versions.")
    return sorted(catalog.versions, key=version, reverse=True)


def final_server_image(manifest, release):
    """Require a checksummed final image; beta/RC names cannot qualify."""
    filename = "ubuntu-" + release + "-live-server-amd64.iso"
    entries, parsed = [], 0
    for line in manifest.splitlines():
        match = re.fullmatch(r"([0-9a-fA-F]{64})\s+[ *](\S+)", line)
        if match:
            parsed += 1
            if match.group(2) == filename:
                entries.append(match.group(1).lower())
    if not parsed:
        raise CheckError("Official image checksums contain no recognized entries.")
    if len(entries) > 1:
        raise CheckError("Official final-image metadata is ambiguous.")
    return {"filename": filename, "sha256": entries[0]} if entries else None


def normal_releases(text):
    releases = []
    for paragraph in re.split(r"\n\s*\n", text.strip()):
        fields = {}
        for line in paragraph.splitlines():
            key, separator, value = line.partition(":")
            if separator and key in ("Dist", "Version", "Supported"):
                if key in fields:
                    raise CheckError("Ordinary upgrade feed has duplicate fields.")
                fields[key] = value.strip()
        if not fields:
            continue
        if set(fields) != {"Dist", "Version", "Supported"} or fields["Supported"] not in ("0", "1"):
            raise CheckError("Ordinary upgrade feed is incomplete or unrecognized.")
        release = fields["Version"].removesuffix(" LTS")
        version(release)
        if not re.fullmatch(r"[a-z]+", fields["Dist"]):
            raise CheckError("Ordinary upgrade feed contains an invalid release name.")
        releases.append({"release": release, "codename": fields["Dist"],
                         "supported": fields["Supported"] == "1"})
    if not releases:
        raise CheckError("Ordinary upgrade feed contains no recognized releases.")
    return releases


def read_local(os_path=Path("/etc/os-release"), prompt_path=Path("/etc/update-manager/release-upgrades")):
    try:
        text = os_path.read_text()
        fields = {}
        for line in text.splitlines():
            key, separator, value = line.partition("=")
            if separator and key in ("ID", "VERSION_ID"):
                if key in fields:
                    raise CheckError("Local operating-system metadata is ambiguous.")
                fields[key] = value.strip().strip('"')
        if fields.get("ID") != "ubuntu":
            raise CheckError("This release check requires Ubuntu metadata.")
        release = fields.get("VERSION_ID", "")
        version(release)
        prompts = re.findall(r"^\s*Prompt\s*=\s*(lts|normal|never)\s*(?:#.*)?$", prompt_path.read_text(), re.MULTILINE)
        if len(prompts) != 1:
            raise CheckError("Release-upgrader Prompt setting is missing or ambiguous.")
        return release, prompts[0]
    except (OSError, UnicodeError):
        raise CheckError("Local Ubuntu release settings could not be read.") from None


def collect(current, prompt, fetch):
    current_key = version(current)[:2]
    candidates = released_versions(fetch(RELEASE_ROOT))
    feed = normal_releases(fetch(NORMAL_FEED))
    newer = [item for item in candidates if version(item)[:2] > current_key]
    latest, image = None, None
    for candidate in newer[:MAX_CATALOGS]:
        manifest = fetch(RELEASE_ROOT + candidate + "/SHA256SUMS")
        image = final_server_image(manifest, candidate)
        if image:
            latest = candidate
            break
    if len(newer) > MAX_CATALOGS and latest is None:
        raise CheckError("Release catalog search limit reached; newest stable release remains unknown.")
    supported = [item for item in feed if item["supported"] and version(item["release"])[:2] > current_key]
    if supported and latest is None:
        raise CheckError("The ordinary feed offers a newer release, but its final server-image publication could not be established.")
    next_offering = min(supported, key=lambda item: version(item["release"])) if supported else None
    offered = latest is not None and any(item["supported"] and version(item["release"])[:2] == version(latest)[:2] for item in feed)
    blockers, actions = [], []
    if latest:
        if not offered:
            blockers.append("The published newer stable release is absent or unsupported in the ordinary meta-release upgrade feed.")
            actions.append("Recheck the ordinary official upgrade feed hourly; use the supported release upgrader once its stable path opens.")
        if prompt != "normal":
            blockers.append("The local release-upgrader Prompt setting is " + prompt + ", which does not request every stable release.")
            actions.append("Set Prompt=normal as part of the qualified stable upgrade path so interim releases are considered.")
        blockers.append("Guardian, Docker, recovery and host-release compatibility are not established by this discovery check.")
        actions.append("Qualify the released target in a representative disposable environment, preserve a coherent current Guardian/model recovery point, then perform and verify the supported upgrade.")
    return {"schema_version": 1, "observed_at_utc": datetime.now(timezone.utc).isoformat(),
            "status": "attention" if latest else "current", "current_installed_series": current,
            "release_upgrader_prompt": prompt, "newer_stable_release": latest,
            "published_final_server_image": image if latest else None,
            "normal_upgrade_feed": NORMAL_FEED, "newest_stable_normally_offered": offered,
            "next_normal_supported_release": next_offering,
            "qualification": "not established by this discovery check", "blockers": blockers,
            "next_actions": actions, "installation_performed": False,
            "limitations": ["Publication is checked over official HTTPS; this does not verify an image signature or its runtime.",
                            "No release-upgrader process is run. Development or forced upgrades are never attempted.",
                            "This checks release-series upgrades; package and point-release activation require separate checks."]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit machine-readable status")
    args = parser.parse_args(argv)
    fetch = Fetcher()
    try:
        current, prompt = read_local()
        report = collect(current, prompt, fetch)
        code = 2 if report["status"] == "attention" else 0
    except CheckError as error:
        report = {"schema_version": 1, "observed_at_utc": datetime.now(timezone.utc).isoformat(),
                  "status": "unknown", "errors": [str(error)], "installation_performed": False,
                  "next_actions": ["Repair release-discovery checks and retry promptly; an unavailable check does not establish that Ubuntu is current."]}
        code = 1
    report["sources"] = fetch.evidence
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(json.dumps(report, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
