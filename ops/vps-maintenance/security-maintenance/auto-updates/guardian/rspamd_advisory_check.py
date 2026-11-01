#!/usr/bin/env python3
"""Report newer Rspamd release lines for review; never deploy or diagnose CVEs."""

import argparse
from datetime import datetime, timezone
import importlib.machinery
import json
import os
from pathlib import Path
import re
import stat
import sys
from urllib.parse import parse_qs, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
import xml.etree.ElementTree as ET


API_HOST = "api.github.com"
API_PATH = "/repos/rspamd/rspamd/releases"
PER_PAGE = 100
MAX_PAGES = 10
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
RSPAMD_PIN = re.compile(r"rspamd/rspamd:(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)@sha256:[a-f0-9]{64}\Z")
RELEASE_TAG = re.compile(r"v?(0|[1-9]\d*)\.(0|[1-9]\d*)(?:\.(0|[1-9]\d*))?\Z")
SECURITY_WORDS = re.compile(r"\b(?:security|vulnerabilit(?:y|ies)|cve-\d{4}-\d{4,}|critfix|fail[ -]open|remote code execution|memory[ -]safety)\b", re.I)
LINK = re.compile(r'\s*<([^>]+)>\s*;\s*rel="([^"]+)"(?:\s*;[^,]*)?\s*\Z')
CHECKER = Path("/usr/local/libexec/vps-docker-security-check")
MAINTENANCE = "/usr/local/libexec/mail-guardian-maintenance"
RELEASE_COMPOSE = Path("/opt/mail-guardian/current/deploy/compose.yaml")
FEED_URL = "https://docs.rspamd.com/rss/changelog.xml"
CHANGELOG_HOST = "docs.rspamd.com"


def load_host_checker():
    """Import only the existing, root-controlled deployed checker and ancestors."""
    for path in (CHECKER, *CHECKER.parents):
        entry = path.lstat()
        if entry.st_uid != 0 or entry.st_mode & 0o022 or stat.S_ISLNK(entry.st_mode):
            raise ValueError("security checker path is not root-controlled")
        if path == CHECKER and (not stat.S_ISREG(entry.st_mode) or entry.st_nlink != 1):
            raise ValueError("security checker is not a single-link regular file")
        if path != CHECKER and not stat.S_ISDIR(entry.st_mode):
            raise ValueError("security checker ancestor is not a directory")
    previous = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        return importlib.machinery.SourceFileLoader("vps_docker_security_check", str(CHECKER)).load_module()
    finally:
        sys.dont_write_bytecode = previous


def installed_version(compose, checker, release_compose=RELEASE_COMPOSE, maintenance=MAINTENANCE):
    """Bind version to rendered service name, deployed helper and running container."""
    before = Path(compose).read_bytes()
    if before != Path(release_compose).read_bytes():
        raise ValueError("active Compose and release template differ")
    expected = checker.expected_service_images(str(compose))
    if not isinstance(expected, dict) or set(expected) != {"rspamd", "redis", "unbound"}:
        raise ValueError("could not establish Guardian service images")
    image = expected["rspamd"]
    pin = RSPAMD_PIN.fullmatch(image) if isinstance(image, str) else None
    if not pin:
        raise ValueError("Rspamd service does not have a canonical version and digest pin")
    if checker.rspamd_helper_image(maintenance) != image:
        raise ValueError("Rspamd helper pin differs from Compose")
    rows = checker.running_container_images(expected)
    if (not isinstance(rows, list) or len(rows) != 3
            or {row.get("service") for row in rows if isinstance(row, dict)} != set(expected)
            or any(not isinstance(row, dict) or row.get("matches_compose") is not True
                   or row.get("status") != "running" for row in rows)):
        raise ValueError("Guardian containers do not match running Compose services")
    if Path(compose).read_bytes() != before:
        raise ValueError("Compose changed while version was being established")
    return tuple(int(x) for x in pin.groups())


def validate_url(url, expected_page):
    parsed = urlsplit(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    if (parsed.scheme != "https" or parsed.hostname != API_HOST or parsed.port not in (None, 443)
            or parsed.username or parsed.password or parsed.fragment or parsed.path != API_PATH
            or query != {"per_page": [str(PER_PAGE)], "page": [str(expected_page)]}):
        raise ValueError("unexpected release API URL or pagination parameters")


class RestrictedRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old_query = parse_qs(urlsplit(req.full_url).query, keep_blank_values=True)
        try:
            expected_page = int(old_query["page"][0])
        except (KeyError, IndexError, ValueError) as exc:
            raise ValueError("invalid prior release API page") from exc
        validate_url(newurl, expected_page)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def next_page(link_header, page):
    if not link_header:
        return None
    found, last_pages = [], []
    for part in link_header.split(","):
        match = LINK.fullmatch(part)
        if not match:
            raise ValueError("malformed release pagination header")
        relationships = match.group(2).split()
        if "next" in relationships:
            found.append(match.group(1))
        if "last" in relationships:
            query = parse_qs(urlsplit(match.group(1)).query, keep_blank_values=True)
            raw = query.get("page")
            if not raw or len(raw) != 1 or not re.fullmatch(r"[1-9]\d*", raw[0]):
                raise ValueError("invalid last release page")
            last_page = int(raw[0])
            validate_url(match.group(1), last_page)
            if last_page < page:
                raise ValueError("last release page precedes the current page")
            last_pages.append(last_page)
    if len(found) > 1 or len(last_pages) > 1:
        raise ValueError("ambiguous release pagination")
    if found:
        if last_pages and last_pages[0] <= page:
            raise ValueError("next page exceeds the last release page")
        validate_url(found[0], page + 1)
        return found[0]
    if last_pages and last_pages[0] > page:
        raise ValueError("release pagination omits its next page")
    return None


def releases(opener=None):
    opener = opener or build_opener(RestrictedRedirect())
    url = f"https://{API_HOST}{API_PATH}?per_page={PER_PAGE}&page=1"
    rows, seen_tags, seen_ids = [], set(), set()
    for page in range(1, MAX_PAGES + 1):
        validate_url(url, page)
        request = Request(url, headers={"Accept": "application/vnd.github+json",
                                       "X-GitHub-Api-Version": "2022-11-28",
                                       "User-Agent": "VPS1-Rspamd-Release-Review/1.0"})
        with opener.open(request, timeout=20) as response:
            validate_url(response.geturl(), page)
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            following = next_page(response.headers.get("Link"), page)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ValueError("release API response exceeds limit")
        page_rows = json.loads(raw)
        if not isinstance(page_rows, list) or len(page_rows) > PER_PAGE:
            raise ValueError("invalid release API response")
        for row in page_rows:
            if (not isinstance(row, dict) or not isinstance(row.get("tag_name"), str)
                    or type(row.get("id")) is not int or type(row.get("draft")) is not bool
                    or type(row.get("prerelease")) is not bool):
                raise ValueError("malformed release entry")
            if row["tag_name"] in seen_tags or row["id"] in seen_ids:
                raise ValueError("release pagination repeated an entry")
            seen_tags.add(row["tag_name"])
            seen_ids.add(row["id"])
            rows.append(row)
        if following is None:
            if len(page_rows) == PER_PAGE:
                raise ValueError("full release page has no next-page evidence")
            return rows
        if not page_rows:
            raise ValueError("empty release page unexpectedly has a next page")
        url = following
    raise ValueError("release pagination exceeded limit")


def validate_feed_url(url):
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname != CHANGELOG_HOST or parsed.port not in (None, 443)
            or parsed.username or parsed.password or parsed.fragment or parsed.query
            or parsed.path != "/rss/changelog.xml"):
        raise ValueError("unexpected changelog feed URL")


class RestrictedFeedRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_feed_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def changelog_feed(opener=None):
    """Read bounded official changelog, rejecting malformed or duplicate items."""
    opener = opener or build_opener(RestrictedFeedRedirect())
    validate_feed_url(FEED_URL)
    request = Request(FEED_URL, headers={"User-Agent": "VPS1-Rspamd-Release-Review/1.0",
                                        "Accept": "application/rss+xml,application/xml"})
    with opener.open(request, timeout=20) as response:
        validate_feed_url(response.geturl())
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("changelog feed exceeds limit")
    # ElementTree accepts UTF-16, in which a byte-level DTD check can miss
    # declarations. Require UTF-8 before checking for XML entity expansion.
    content = raw.decode("utf-8-sig", errors="strict")
    if "\x00" in content:
        raise ValueError("changelog feed contains unsupported encoding")
    header = re.match(r"\s*<\?xml\s+([^?]*)\?>", content, re.I)
    if header:
        encoding = re.search(r"\bencoding\s*=\s*(['\"])([^'\"]+)\1", header.group(1), re.I)
        if encoding and encoding.group(2).lower() != "utf-8":
            raise ValueError("changelog feed declares an unsupported encoding")
    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", content, re.I):
        raise ValueError("changelog feed contains unsupported XML declarations")
    root = ET.fromstring(content)
    items = root.findall("./channel/item")
    if root.tag != "rss" or not 1 <= len(items) <= 100:
        raise ValueError("unexpected changelog feed structure")
    output = {}
    for item in items:
        link, description = item.findtext("link"), item.findtext("description")
        if not isinstance(link, str) or not isinstance(description, str) or not description.strip():
            raise ValueError("changelog item is missing a link or description")
        parsed = urlsplit(link)
        match = re.fullmatch(r"/changelog/(v?(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*))?)/?", parsed.path)
        if (parsed.scheme != "https" or parsed.hostname != CHANGELOG_HOST or parsed.port not in (None, 443)
                or parsed.username or parsed.password or parsed.query or parsed.fragment or not match):
            raise ValueError("changelog item has an unexpected link")
        version_match = RELEASE_TAG.fullmatch(match.group(1))
        version = tuple(int(x or 0) for x in version_match.groups())
        if version in output:
            raise ValueError("changelog feed repeats a version")
        output[version] = {"security_language_present": bool(SECURITY_WORDS.search(description)),
                           "notes_present": True, "release_notes": link}
    return output


def review(installed, rows, changelog):
    if (not isinstance(installed, tuple) or len(installed) != 3
            or any(type(x) is not int or x < 0 for x in installed)):
        raise ValueError("invalid installed version")
    found_installed = False
    newer, seen_versions = [], set()
    for row in rows:
        if row["draft"] or row["prerelease"]:
            continue
        tag = row["tag_name"]
        match = RELEASE_TAG.fullmatch(tag)
        if not match:
            raise ValueError("published release has an unrecognized version tag")
        version = tuple(int(x or 0) for x in match.groups())
        if version in seen_versions:
            raise ValueError("published releases repeat a semantic version")
        seen_versions.add(version)
        if version == installed:
            found_installed = True
        # The official feed is limited. If it no longer covers any release
        # since our installed version, flag incomplete review rather than
        # treating the absence of a security keyword as a clean result.
        if version >= installed and version not in changelog:
            raise ValueError("official changelog feed does not cover a relevant release")
        if version[:2] <= installed[:2]:
            continue
        published = row.get("published_at")
        if not isinstance(published, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", published):
            raise ValueError("release has an invalid publication time")
        newer.append({"version": ".".join(map(str, version)), "published_at": published,
                      **changelog[version]})
    if not found_installed:
        raise ValueError("installed Rspamd version is absent from the enumerated public releases")
    if any(version >= installed and version not in seen_versions for version in changelog):
        raise ValueError("release API does not cover a relevant official changelog item")
    newer.sort(key=lambda item: tuple(map(int, item["version"].split("."))), reverse=True)
    return newer


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose", default="/etc/mail-guardian/pilot/deploy/compose.yaml")
    args = parser.parse_args()
    report = {"checked_at_utc": datetime.now(timezone.utc).isoformat(), "mode": "release_review_only",
              "installed_version": None, "newer_release_lines": [], "errors": [],
              "limitations": ["Reports published Rspamd release notes in newer major or minor lines, not vulnerability applicability or image compatibility.",
                              "Security-word matching is heuristic and can miss fixes or match unrelated text; every newer line requires review.",
                              "No image is pulled, installed or updated; public release feeds do not cover every possible advisory or backport.",
                              "Container checks establish configured references and running state, not loaded image-content integrity or service health."]}
    try:
        checker = load_host_checker()
        installed = installed_version(args.compose, checker)
        report["installed_version"] = ".".join(map(str, installed))
        report["newer_release_lines"] = review(installed, releases(), changelog_feed())
        if installed_version(args.compose, checker) != installed:
            raise ValueError("running Rspamd changed during release review")
    except Exception as exc:
        # API responses and release bodies can contain untrusted text: don't echo them.
        report["errors"].append("release review incomplete: " + type(exc).__name__)
    report["attention"] = bool(report["newer_release_lines"])
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if report["errors"] else 2 if report["attention"] else 0


if __name__ == "__main__":
    sys.exit(main())
