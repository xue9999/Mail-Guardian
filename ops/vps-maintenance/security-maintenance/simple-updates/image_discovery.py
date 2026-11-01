#!/usr/bin/env python3
"""Read-only Guardian image discovery; no candidate is automatically installed.

The highest strict three-part non-prerelease GitHub release is cross-checked
against its exact publisher tag on Docker Hub. A missing image is an error,
not an instruction to install an older version. JSON output; 0 = current,
2 = candidate, 1 = incomplete/failed check (which takes precedence).
"""

import argparse
import datetime as dt
import json
from pathlib import Path
import re
import sys
import urllib.error
import urllib.request
import urllib.parse

SPECS = {
    "redis": ("redis/redis", "library/redis", "", "-alpine"),
    "rspamd/rspamd": ("rspamd/rspamd", "rspamd/rspamd", "", ""),
    "klutchell/unbound": ("NLnetLabs/unbound", "klutchell/unbound", "release-", ""),
}
PIN = re.compile(r"([^:@\s]+):((?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))(-[a-z0-9.]+)?@(sha256:[0-9a-f]{64})\Z")
VERSION = re.compile(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
IMAGE = re.compile(r"^\s*image:\s*([^\s#]+)\s*(?:#.*)?$")
PAGE_SIZE = 100
MAX_PAGES = 20
MAX_BYTES = 2 * 1024 * 1024


class DiscoveryError(Exception):
    pass


def version(value):
    match = VERSION.fullmatch(value) if isinstance(value, str) else None
    if not match:
        raise DiscoveryError("invalid stable version")
    return tuple(int(x) for x in match.groups())


def parse_compose(path):
    pins = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        found = IMAGE.fullmatch(line)
        if not found:
            continue
        ref = found.group(1).strip("\"'")
        match = PIN.fullmatch(ref)
        if not match:
            raise DiscoveryError("an image is not pinned to a strict version and digest")
        repo, ver, suffix, digest = match.groups()
        if repo not in SPECS or (suffix or "") != SPECS[repo][3] or repo in pins:
            raise DiscoveryError("unexpected, duplicate, or wrong-variant image")
        pins[repo] = {"version": ver, "digest": digest, "ref": ref}
    if set(pins) != set(SPECS):
        raise DiscoveryError("expected exactly the three Guardian image pins")
    return pins


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise DiscoveryError("unexpected HTTP redirect")


def fetch_json(url):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname not in ("api.github.com", "hub.docker.com")
            or parsed.port not in (None, 443) or parsed.username or parsed.password or parsed.fragment):
        raise DiscoveryError("unexpected source URL")
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "Guardian-stable-discovery/1.0"})
    opener = urllib.request.build_opener(NoRedirect())
    with opener.open(req, timeout=20) as response:
        if response.geturl() != url:
            raise DiscoveryError("unexpected response URL")
        raw = response.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise DiscoveryError("response exceeds size limit")
    try:
        return json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise DiscoveryError("invalid JSON response") from exc


def latest_release(project, prefix, fetch=fetch_json):
    releases, seen_ids, seen_tags = [], set(), set()
    # Request the next page until a short page, not just the first page or the
    # GitHub 'latest' designation, which does not imply highest version.
    for page in range(1, MAX_PAGES + 1):
        url = f"https://api.github.com/repos/{project}/releases?per_page={PAGE_SIZE}&page={page}"
        rows = fetch(url)
        if not isinstance(rows, list) or len(rows) > PAGE_SIZE:
            raise DiscoveryError("invalid GitHub release page")
        for row in rows:
            if (not isinstance(row, dict) or type(row.get("id")) is not int
                    or type(row.get("draft")) is not bool or type(row.get("prerelease")) is not bool
                    or not isinstance(row.get("tag_name"), str)):
                raise DiscoveryError("malformed GitHub release record")
            ident, tag = row["id"], row["tag_name"]
            if ident in seen_ids or tag in seen_tags:
                raise DiscoveryError("duplicate release across pages")
            seen_ids.add(ident)
            seen_tags.add(tag)
            if row["draft"] or row["prerelease"] or not tag.startswith(prefix):
                continue
            candidate = tag[len(prefix):]
            if VERSION.fullmatch(candidate):
                releases.append(candidate)
        if len(rows) < PAGE_SIZE:
            if not releases:
                raise DiscoveryError("no strict stable release found")
            return max(releases, key=version)
    raise DiscoveryError("GitHub release pagination exceeded limit")


def image_for(hub_repo, tag, fetch=fetch_json):
    url = f"https://hub.docker.com/v2/repositories/{hub_repo}/tags/{tag}"
    data = fetch(url)
    if not isinstance(data, dict) or data.get("name") != tag or data.get("tag_status") != "active":
        raise DiscoveryError("exact publisher tag is missing, inactive or mismatched")
    index = data.get("digest")
    images = data.get("images")
    if not isinstance(index, str) or not DIGEST.fullmatch(index) or not isinstance(images, list):
        raise DiscoveryError("invalid registry index or platform list")
    amd64 = [i for i in images if isinstance(i, dict) and i.get("os") == "linux" and i.get("architecture") == "amd64"]
    if len(amd64) != 1 or not isinstance(amd64[0].get("digest"), str) or not DIGEST.fullmatch(amd64[0]["digest"]):
        raise DiscoveryError("missing or ambiguous linux/amd64 image digest")
    return index, amd64[0]["digest"]


def compatible_patch(hub_repo, installed, suffix, fetch=fetch_json):
    """Find a same-minor registry fallback when the latest image is missing."""
    major, minor, current = version(installed["version"])
    prefix = f"{major}.{minor}."
    path = "/v2/repositories/" + hub_repo + "/tags"
    query = urllib.parse.urlencode({"name": prefix, "page_size": 100})
    url = "https://hub.docker.com" + path + "?" + query
    seen, names, rows, count = set(), set(), [], None
    for _ in range(MAX_PAGES):
        parsed = urllib.parse.urlsplit(url)
        if (parsed.scheme != "https" or parsed.hostname != "hub.docker.com" or parsed.port not in (None, 443)
                or parsed.username or parsed.password or parsed.fragment or parsed.path.rstrip('/') != path
                or urllib.parse.parse_qs(parsed.query).get('name') != [prefix] or url in seen):
            raise DiscoveryError('unexpected fallback registry pagination URL')
        seen.add(url)
        page = fetch(url)
        if not isinstance(page, dict) or type(page.get('count')) is not int or not isinstance(page.get('results'), list):
            raise DiscoveryError('invalid fallback registry page')
        if count is None: count = page['count']
        if count != page['count'] or count < 0: raise DiscoveryError('fallback registry count changed')
        for row in page['results']:
            if not isinstance(row, dict) or not isinstance(row.get('name'), str) or row['name'] in names:
                raise DiscoveryError('invalid or repeated fallback registry tag')
            names.add(row['name'])
            tag = row['name']
            match = re.fullmatch(re.escape(prefix) + r'(0|[1-9]\d*)' + re.escape(suffix), tag)
            if match and int(match.group(1)) >= current and row.get('tag_status') == 'active':
                rows.append((int(match.group(1)), tag))
        url = page.get('next')
        if url is None:
            if len(names) != count or installed['version'] + suffix not in names:
                raise DiscoveryError('fallback registry pagination incomplete')
            if not rows: return None
            _, tag = max(rows)
            index, platform = image_for(hub_repo, tag, fetch)
            if tag == installed['version'] + suffix and index == installed['digest']:
                return None
            return {'tag': tag, 'index_digest': index, 'linux_amd64_digest': platform}
        if not isinstance(url, str): raise DiscoveryError('invalid fallback pagination')
    raise DiscoveryError('fallback registry pagination exceeded limit')


def discover(pins, fetch=fetch_json, *, patch_only=False):
    out = {"checked_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(), "mode": "discovery_only", "images": [], "errors": []}
    for repo, (project, hub_repo, prefix, suffix) in SPECS.items():
        try:
            installed = pins[repo]
            newest = latest_release(project, prefix, fetch)
            if version(newest) < version(installed["version"]):
                raise DiscoveryError("installed version is newer than highest upstream stable release")
            if patch_only and version(newest)[:2] != version(installed["version"])[:2]:
                # Detect newer lines, but continue patches in the installed line.
                # Manual qualification uses the normal unrestricted discovery.
                candidate = compatible_patch(hub_repo, installed, suffix, fetch)
                if candidate:
                    candidate['ref'] = f"{repo}:{candidate['tag']}@{candidate['index_digest']}"
                out["images"].append({"repo": repo, "installed": installed,
                                      "upstream_version": newest, "candidate": candidate,
                                      "manual_review": "New major/minor line requires operator review and qualification."})
                continue
            tag = newest + suffix
            try:
                index, platform = image_for(hub_repo, tag, fetch)
            except urllib.error.HTTPError as exc:
                if exc.code != 404:
                    raise
                blocker = f"upstream {newest}: image {hub_repo}:{tag} is not published"
                out["errors"].append({"repo": repo, "error": blocker})
                try:
                    candidate = compatible_patch(hub_repo, installed, suffix, fetch)
                except (DiscoveryError, OSError, ValueError, urllib.error.URLError) as fallback_error:
                    out["errors"].append({"repo": repo, "error": 'compatible fallback: ' + str(fallback_error)[:250]})
                    continue
                if candidate:
                    candidate['ref'] = f"{repo}:{candidate['tag']}@{candidate['index_digest']}"
                out["images"].append({"repo": repo, "installed": installed, "upstream_version": newest,
                                      "candidate": candidate, "blocker": blocker, "fallback": True})
                continue
            except (DiscoveryError, OSError, ValueError, urllib.error.URLError) as exc:
                raise DiscoveryError(f"upstream {newest}: image {hub_repo}:{tag} unavailable or invalid: {exc}") from exc
            changed = newest != installed["version"] or index != installed["digest"]
            out["images"].append({"repo": repo, "installed": installed, "upstream_version": newest,
                "candidate": {"tag": tag, "index_digest": index, "linux_amd64_digest": platform,
                              "ref": f"{repo}:{tag}@{index}"} if changed else None})
        except (DiscoveryError, OSError, ValueError, KeyError, urllib.error.URLError) as exc:
            out["errors"].append({"repo": repo, "error": f"{type(exc).__name__}: {str(exc)[:300]}"})
    out["attention"] = any(row["candidate"] for row in out["images"])
    out["manual_review"] = [dict(repo=row["repo"], detected=row["upstream_version"],
                                 reason=row["manual_review"]) for row in out["images"] if row.get("manual_review")]
    out["limitations"] = ["Detection only: no image is pulled, tested or installed.",
        "GitHub release and Docker Hub metadata do not prove publisher authenticity, image contents, compatibility or security.",
        "If the newest upstream image is absent, a same-minor publisher tag may be reported as an unqualified fallback; the blocker remains an error.",
        "Guardian application updates are outside this image check."]
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose", default="/etc/mail-guardian/pilot/deploy/compose.yaml")
    args = parser.parse_args(argv)
    try:
        result = discover(parse_compose(args.compose))
    except (OSError, UnicodeError, DiscoveryError) as exc:
        result = {"mode": "discovery_only", "images": [], "errors": [{"error": str(exc)}], "attention": False}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["errors"] else 2 if result["attention"] else 0


if __name__ == "__main__":
    sys.exit(main())
