#!/usr/bin/env python3
"""Report newer upstream Unbound releases and recent advisories; never deploy."""

import argparse
from datetime import date, datetime, timezone
from html.parser import HTMLParser
import importlib.machinery
import json
from pathlib import Path
import re
import signal
import stat
import sys
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


CHECKER = Path('/usr/local/libexec/vps-docker-security-check')
COMPOSE = '/etc/mail-guardian/pilot/deploy/compose.yaml'
RELEASE_COMPOSE = Path('/opt/mail-guardian/current/deploy/compose.yaml')
DOWNLOAD_URL = 'https://www.nlnetlabs.nl/projects/unbound/download/'
ADVISORY_URL = 'https://www.nlnetlabs.nl/projects/unbound/security-advisories/'
GITHUB_URL = 'https://api.github.com/repos/NLnetLabs/unbound/releases/latest'
HUB_PREFIX = 'https://hub.docker.com/v2/repositories/klutchell/unbound/tags/'
MAX_BYTES = 2 * 1024 * 1024
NUM = r'(?:0|[1-9][0-9]{0,4})'
VERSION = rf'({NUM})\.({NUM})\.({NUM})'
PIN = re.compile(rf'klutchell/unbound:{VERSION}@sha256:[0-9a-f]{{64}}\Z')
CVE = re.compile(r'CVE-[0-9]{4}-[0-9]{4,}\Z')
DIGEST = re.compile(r'sha256:[a-f0-9]{64}\Z')
MONTHS = {name: index for index, name in enumerate(
    ('January', 'February', 'March', 'April', 'May', 'June', 'July', 'August',
     'September', 'October', 'November', 'December'), start=1)}
MONTHS.update({name[:3]: index for name, index in tuple(MONTHS.items())})


def load_host_checker():
    """Import only the root-controlled deployed checker and trusted ancestors."""
    for path in (CHECKER, *CHECKER.parents):
        entry = path.lstat()
        if entry.st_uid != 0 or entry.st_mode & 0o022 or stat.S_ISLNK(entry.st_mode):
            raise ValueError('security checker path is not root-controlled')
        if path == CHECKER and (not stat.S_ISREG(entry.st_mode) or entry.st_nlink != 1):
            raise ValueError('security checker is not a single-link regular file')
        if path != CHECKER and not stat.S_ISDIR(entry.st_mode):
            raise ValueError('security checker ancestor is not a directory')
    previous = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        return importlib.machinery.SourceFileLoader('vps_docker_security_check', str(CHECKER)).load_module()
    finally:
        sys.dont_write_bytecode = previous


def installed_version(compose, checker, release_compose=RELEASE_COMPOSE):
    """Bind version to the deployed Compose and matching configured containers."""
    before = Path(compose).read_bytes()
    if before != Path(release_compose).read_bytes():
        raise ValueError('active Compose and release template differ')
    expected = checker.expected_service_images(str(compose))
    if not isinstance(expected, dict) or set(expected) != {'rspamd', 'redis', 'unbound'}:
        raise ValueError('could not establish Guardian service images')
    image = expected['unbound']
    match = PIN.fullmatch(image) if isinstance(image, str) else None
    if not match:
        raise ValueError('Unbound service lacks a canonical version and digest pin')
    rows = checker.running_container_images(expected)
    if (not isinstance(rows, list) or len(rows) != 3
            or {row.get('service') for row in rows if isinstance(row, dict)} != set(expected)
            or any(not isinstance(row, dict) or row.get('matches_compose') is not True
                   or row.get('status') != 'running' for row in rows)):
        raise ValueError('Guardian containers do not match running Compose services')
    if Path(compose).read_bytes() != before:
        raise ValueError('Compose changed during version check')
    return tuple(int(x) for x in match.groups()), image


def validate_url(url, expected):
    if not isinstance(url, str) or url != expected:
        raise ValueError('unexpected source URL or redirect')
    parsed = urlsplit(url)
    if parsed.scheme != 'https' or parsed.username or parsed.password or parsed.fragment:
        raise ValueError('source URL is not a clean HTTPS URL')


class ExactRedirect(HTTPRedirectHandler):
    def __init__(self, expected):
        super().__init__()
        self.expected = expected

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_url(newurl, self.expected)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url, opener=None):
    opener = opener or build_opener(ExactRedirect(url))
    request = Request(url, headers={'User-Agent': 'VPS1-Unbound-Release-Review/1.0',
                                    'Accept': 'application/json,text/html'})
    with opener.open(request, timeout=20) as response:
        validate_url(response.geturl(), url)
        raw = response.read(MAX_BYTES + 1)
    if not raw or len(raw) > MAX_BYTES:
        raise ValueError('source is empty or exceeds the size limit')
    if b'\x00' in raw:
        raise ValueError('source contains unsupported encoding')
    return raw.decode('utf-8', errors='strict')


def require_complete_html(text):
    if (not re.search(r'<html\b', text, re.I) or not re.search(r'</html\s*>', text, re.I)
            or not re.search(r'<body\b', text, re.I) or not re.search(r'</body\s*>', text, re.I)):
        raise ValueError('incomplete HTML document')


class Releases(HTMLParser):
    def __init__(self, installed):
        super().__init__(convert_charrefs=True)
        self.installed = installed
        self.finished = False
        self.heading = None
        self.dt = None
        self.dd = None
        self.field = None
        self.current_version = None
        self.current_count = 0
        self.version = None
        self.releases = {}
        self.texts = {}

    def handle_starttag(self, tag, attrs):
        if self.finished:
            return
        if tag in ('h2', 'h3'):
            self.heading = []
        elif tag == 'dt' and self.version is not None:
            self.dt = []
        elif tag == 'dd' and self.version is not None and self.field == 'Date:':
            self.dd = []

    def handle_data(self, data):
        if self.finished:
            return
        if self.heading is not None:
            self.heading.append(data)
        elif self.version is not None:
            self.texts[self.version].append(data)
        if self.dt is not None:
            self.dt.append(data)
        if self.dd is not None:
            self.dd.append(data)

    def handle_endtag(self, tag):
        if self.finished:
            return
        if tag in ('h2', 'h3') and self.heading is not None:
            value = ' '.join(''.join(self.heading).split())
            self.heading = None
            match = re.fullmatch(rf'Unbound {VERSION}( \(Current version\))?', value)
            if match:
                version = tuple(int(x) for x in match.groups()[:3])
                if version in self.releases:
                    raise ValueError('release page repeats a version')
                self.releases[version] = None
                self.texts[version] = []
                self.version = version
                self.field = None
                if match.group(4):
                    self.current_version = version
                    self.current_count += 1
            elif value.startswith('Unbound ') and re.search(r'\d', value):
                raise ValueError('unrecognized version heading')
        elif tag == 'dt' and self.dt is not None:
            self.field = ' '.join(''.join(self.dt).split())
            self.dt = None
        elif tag == 'dd' and self.dd is not None:
            value = ' '.join(''.join(self.dd).split())
            self.dd = None
            match = re.fullmatch(r'([0-9]{1,2}) ([A-Za-z]+), ([0-9]{4})', value)
            if not match or match.group(2) not in MONTHS:
                raise ValueError('release page has an invalid date')
            try:
                parsed = date(int(match.group(3)), MONTHS[match.group(2)], int(match.group(1)))
            except ValueError as exc:
                raise ValueError('release page has an invalid date') from exc
            if self.releases[self.version] is not None:
                raise ValueError('release page repeats a release date')
            self.releases[self.version] = parsed
            if self.version == self.installed:
                self.finished = True


class CurrentHeadings(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.heading = None
        self.versions = []
        self.published_versions = []

    def handle_starttag(self, tag, attrs):
        if tag in ('h2', 'h3'):
            self.heading = []

    def handle_data(self, data):
        if self.heading is not None:
            self.heading.append(data)

    def handle_endtag(self, tag):
        if tag in ('h2', 'h3') and self.heading is not None:
            value = ' '.join(''.join(self.heading).split())
            self.heading = None
            published = re.fullmatch(rf'Unbound {VERSION}(?: \(Current version\))?', value)
            if published:
                self.published_versions.append(tuple(int(x) for x in published.groups()))
            if 'Current version' in value:
                match = re.fullmatch(rf'Unbound {VERSION} \(Current version\)', value)
                if not match:
                    raise ValueError('unrecognized current version heading')
                self.versions.append(tuple(int(x) for x in match.groups()))


def parse_releases(text, installed):
    require_complete_html(text)
    headings = CurrentHeadings()
    headings.feed(text)
    headings.close()
    if (installed not in headings.published_versions or
            any(left <= right for left, right in zip(headings.published_versions, headings.published_versions[1:]))):
        raise ValueError('release page version sequence is incomplete or out of order')
    parser = Releases(installed)
    parser.feed(text)
    parser.close()
    if (parser.current_count != 1 or headings.versions != [parser.current_version]
            or not parser.releases or installed not in parser.releases):
        raise ValueError('release page omits or ambiguously identifies current or installed version')
    if parser.current_version != max(parser.releases):
        raise ValueError('current release is not the highest published version')
    relevant = {v: d for v, d in parser.releases.items() if v >= installed}
    if any(d is None for d in relevant.values()):
        raise ValueError('a relevant release has no publication date')
    if installed > parser.current_version:
        raise ValueError('installed version exceeds reported current release')
    mentioned_cves = set()
    for version, chunks in parser.texts.items():
        if version > installed:
            mentioned_cves.update(re.findall(r'\bCVE-[0-9]{4}-[0-9]{4,}\b', ''.join(chunks)))
    return parser.current_version, relevant, mentioned_cves


class Advisories(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.in_table = False
        self.in_th = False
        self.in_td = False
        self.field = []
        self.value = []
        self.fields = {}
        self.entries = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'table' and 'field-list' in attrs.get('class', '').split():
            if self.in_table:
                raise ValueError('nested advisory field table')
            self.in_table, self.fields = True, {}
        elif self.in_table and tag == 'tr':
            self.field, self.value = [], []
        elif self.in_table and tag == 'th':
            self.in_th = True
        elif self.in_table and tag == 'td':
            self.in_td = True

    def handle_data(self, data):
        if self.in_th:
            self.field.append(data)
        if self.in_td:
            self.value.append(data)

    def handle_endtag(self, tag):
        if self.in_table and tag == 'th':
            self.in_th = False
        elif self.in_table and tag == 'td':
            self.in_td = False
        elif self.in_table and tag == 'tr':
            key = ' '.join(''.join(self.field).split()).rstrip(':')
            value = ' '.join(''.join(self.value).split())
            if not key:
                raise ValueError('malformed advisory field')
            if key in ('Date', 'CVE', 'Affects'):
                if key in self.fields:
                    raise ValueError('duplicate advisory field')
                self.fields[key] = value
        elif self.in_table and tag == 'table':
            self.in_table = False
            identifier = self.fields.get('CVE')
            raw_date = self.fields.get('Date', '')
            affects = self.fields.get('Affects')
            if not isinstance(identifier, str) or not CVE.fullmatch(identifier):
                raise ValueError('advisory has no canonical CVE identifier')
            if not isinstance(affects, str) or not affects.strip():
                raise ValueError('advisory has no affected-version range')
            dates = re.findall(r'\b[0-9]{4}-[0-9]{2}-[0-9]{2}\b', raw_date)
            if not dates or not raw_date.startswith(dates[0]):
                raise ValueError('advisory has an invalid date')
            try:
                modified = max(date.fromisoformat(value) for value in dates)
            except ValueError as exc:
                raise ValueError('advisory has an invalid date') from exc
            self.entries.append({'cve': identifier, 'date': modified.isoformat(), 'affects': affects})


def affected_version(installed, description):
    """Conservatively compare the vendor's known version-range grammar.

    Conditional suffixes such as 'compiled with ECS' are intentionally ignored:
    matching the version range prompts review, not an exploitability claim.
    Unknown grammar is an error, never an assertion that the server is safe.
    """
    part = r'((?:0|[1-9][0-9]{0,4})\.(?:0|[1-9][0-9]{0,4})(?:\.(?:0|[1-9][0-9]{0,4}))?(?:p[0-9]+)?)'
    expression = (rf'Unbound (?:(?:version )?{part} )?up to and including '
                  rf'(?:(?:version|Unbound) )?{part}(?: (compiled and configured for ECS support))?')
    match = re.fullmatch(expression, description)
    if match:
        lower_raw, upper_raw, _condition = match.groups()
    else:
        match = re.fullmatch(rf'Unbound {part} and earlier versions', description)
        if not match:
            raise ValueError('unrecognized affected-version range')
        lower_raw, upper_raw = None, match.group(1)
    def normalize(value):
        if value is None:
            return (0, 0, 0)
        numbers = re.sub(r'p[0-9]+\Z', '', value).split('.')
        return tuple(int(item) for item in (numbers + ['0'])[:3])
    lower, upper = normalize(lower_raw), normalize(upper_raw)
    if lower > upper:
        raise ValueError('inverted affected-version range')
    return lower <= installed <= upper


def parse_advisories(text, installed, required_cves=()):
    require_complete_html(text)
    parser = Advisories()
    parser.feed(text)
    parser.close()
    if parser.in_table or not parser.entries:
        raise ValueError('advisory list is missing or incomplete')
    seen = [entry['cve'] for entry in parser.entries]
    if len(seen) != len(set(seen)):
        raise ValueError('advisory list repeats an identifier')
    if not set(required_cves).issubset(seen):
        raise ValueError('advisory list omits a CVE mentioned in newer release notes')
    return sorted((entry for entry in parser.entries if affected_version(installed, entry['affects'])),
                  key=lambda entry: (entry['date'], entry['cve']), reverse=True)


def verify_latest_github(text, upstream):
    data = json.loads(text)
    if not isinstance(data, dict) or data.get('draft') is not False or data.get('prerelease') is not False:
        raise ValueError('official release record is incomplete')
    match = re.fullmatch(rf'release-{VERSION}', data.get('tag_name', ''))
    if not match or tuple(int(x) for x in match.groups()) != upstream:
        raise ValueError('official release sources disagree')
    published = data.get('published_at')
    if not isinstance(published, str) or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z', published):
        raise ValueError('official release publication time is invalid')
    return published


def check_image(text, tag):
    data = json.loads(text)
    if not isinstance(data, dict) or data.get('name') != tag or data.get('tag_status') != 'active':
        raise ValueError('third-party image tag is inactive or mismatched')
    if not isinstance(data.get('digest'), str) or not DIGEST.fullmatch(data['digest']):
        raise ValueError('third-party image index has an invalid digest')
    images = data.get('images')
    if not isinstance(images, list):
        raise ValueError('third-party image platforms are missing')
    amd64 = [item for item in images if isinstance(item, dict) and item.get('os') == 'linux'
             and item.get('architecture') == 'amd64' and item.get('status') == 'active']
    if len(amd64) != 1 or not isinstance(amd64[0].get('digest'), str) or not DIGEST.fullmatch(amd64[0]['digest']):
        raise ValueError('third-party image has no unique active linux/amd64 digest')
    return {'tag': tag, 'index_digest': data['digest'], 'amd64_digest': amd64[0]['digest']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', default=COMPOSE)
    parser.add_argument('--release-compose', default=str(RELEASE_COMPOSE))
    args = parser.parse_args()
    report = {'checked_at_utc': datetime.now(timezone.utc).isoformat(), 'mode': 'advisory_only',
              'installed': None, 'installed_image': None, 'upstream_current': None, 'newer_upstream': False,
              'third_party_image': None, 'version_range_advisories': [], 'attention': False, 'errors': [],
              'limitations': ['Newer releases and vendor affected-version matches are review signals, not proof of exploitability or installed fixes.',
                              'The installed version is the configured image tag, not an independent binary-version measurement.',
                              'The existing klutchell/unbound image is third-party; a registry digest is not upstream provenance or compatibility proof.',
                              'Conditional vendor ranges are reported conservatively without asserting that conditions are met.',
                              'Only advisories present in the official fetched pages are reviewed; source publication and coverage may be incomplete.']}
    try:
        checker = load_host_checker()
        installed, image = installed_version(args.compose, checker, args.release_compose)
        report['installed'] = '.'.join(map(str, installed))
        report['installed_image'] = image
        latest, releases, required_cves = parse_releases(fetch(DOWNLOAD_URL), installed)
        report['upstream_current'] = '.'.join(map(str, latest))
        report['published_at'] = verify_latest_github(fetch(GITHUB_URL), latest)
        report['version_range_advisories'] = parse_advisories(fetch(ADVISORY_URL), installed, required_cves)
        report['newer_upstream'] = latest > installed
        report['attention'] = report['newer_upstream'] or bool(report['version_range_advisories'])
        if report['newer_upstream']:
            tag = report['upstream_current']
            try:
                data = fetch(HUB_PREFIX + tag)
            except HTTPError as exc:
                if exc.code != 404:
                    raise
                report['third_party_image'] = {'tag': tag, 'available': False}
            else:
                report['third_party_image'] = dict(check_image(data, tag), available=True)
        if installed_version(args.compose, checker, args.release_compose) != (installed, image):
            raise ValueError('deployed Unbound image changed during review')
    except Exception as exc:
        # Avoid echoing untrusted network/error text or local configuration.
        report['errors'].append('release review incomplete: ' + type(exc).__name__)
    print(json.dumps(report, sort_keys=True, indent=2))
    return 1 if report['errors'] else 2 if report['attention'] else 0


def deadline_expired(_signal, _frame):
    raise TimeoutError('overall advisory check deadline exceeded')


if __name__ == '__main__':
    signal.signal(signal.SIGALRM, deadline_expired)
    signal.alarm(180)
    try:
        sys.exit(main())
    finally:
        signal.alarm(0)
