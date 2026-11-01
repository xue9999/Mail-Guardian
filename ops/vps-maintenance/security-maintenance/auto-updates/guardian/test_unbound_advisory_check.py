import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
from urllib.error import HTTPError

import unbound_advisory_check as check


def download(current='1.26.2', installed='1.25.2'):
    return ('<html><body><h2>Unbound ' + current + ' (Current version)</h2>'
            '<dl><dt>Date:</dt><dd>21 October, 2026</dd></dl>'
            '<ul><li>Fix CVE-2026-81642</li></ul>'
            '<h3>Unbound 1.26.1</h3><dl><dt>Date:</dt><dd>16 September, 2026</dd></dl>'
            '<h3>Unbound ' + installed + '</h3><dl><dt>Date:</dt><dd>22 July, 2026</dd></dl>'
            '</body></html>')


def advisory(cve='CVE-2026-81642', disclosed='2026-09-16', affects='Unbound up to and including version 1.26.0'):
    return ('<html><body><table class="docutils field-list"><tr><th>Date:</th><td>' + disclosed + '</td></tr>'
            '<tr><th>CVE:</th><td><a>' + cve + '</a></td></tr>'
            '<tr><th>Affects:</th><td>' + affects + '</td></tr>'
            '<tr><th>Severity:</th><td>Critical</td></tr></table></body></html>')


def github(tag='release-1.26.2', **extra):
    data = {'tag_name': tag, 'draft': False, 'prerelease': False, 'published_at': '2026-10-21T08:55:36Z'}
    data.update(extra)
    return json.dumps(data)


def image(tag='1.26.2', **extra):
    data = {'name': tag, 'tag_status': 'active', 'digest': 'sha256:' + 'a' * 64,
            'images': [{'os': 'linux', 'architecture': 'amd64', 'status': 'active', 'digest': 'sha256:' + 'b' * 64}]}
    data.update(extra)
    return json.dumps(data)


class InstalledVersionTests(unittest.TestCase):
    def test_container_and_compose_version_must_agree(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'compose.yml'
            path.write_text('same version')
            fake = mock.Mock()
            pin = 'klutchell/unbound:1.25.2@sha256:' + 'a' * 64
            fake.expected_service_images.return_value = {'unbound': pin, 'redis': 'r', 'rspamd': 's'}
            fake.running_container_images.return_value = [
                {'service': name, 'matches_compose': True, 'status': 'running'}
                for name in ('unbound', 'redis', 'rspamd')]
            self.assertEqual(check.installed_version(path, fake, path), ((1, 25, 2), pin))
            fake.running_container_images.return_value[0]['matches_compose'] = False
            with self.assertRaisesRegex(ValueError, 'containers'):
                check.installed_version(path, fake, path)
            fake.running_container_images.return_value[0]['matches_compose'] = True
            fake.expected_service_images.return_value['unbound'] = 'other/unbound:1.25.2@sha256:' + 'a' * 64
            with self.assertRaisesRegex(ValueError, 'canonical'):
                check.installed_version(path, fake, path)

    def test_release_and_runtime_drift_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            active, release = Path(directory) / 'active', Path(directory) / 'release'
            active.write_text('active')
            release.write_text('different')
            with self.assertRaisesRegex(ValueError, 'differ'):
                check.installed_version(active, mock.Mock(), release)


class ReleaseTests(unittest.TestCase):
    def test_finds_newer_version_release_date_and_cve(self):
        latest, relevant, cves = check.parse_releases(download(), (1, 25, 2))
        self.assertEqual(latest, (1, 26, 2))
        self.assertEqual(relevant[(1, 25, 2)].isoformat(), '2026-07-22')
        self.assertIn('CVE-2026-81642', cves)

    def test_missing_installed_or_truncated_source_fails(self):
        with self.assertRaisesRegex(ValueError, 'sequence|omits'):
            check.parse_releases(download(installed='1.25.1'), (1, 25, 2))
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            check.parse_releases(download().replace('</html>', ''), (1, 25, 2))

    def test_duplicate_current_heading_fails_even_after_installed(self):
        source = download().replace('</body>', '<h2>Unbound 1.27.0 (Current version)</h2></body>')
        with self.assertRaisesRegex(ValueError, 'ambiguously|sequence'):
            check.parse_releases(source, (1, 25, 2))

    def test_newer_version_hidden_after_installed_heading_fails(self):
        source = download().replace('</body>', '<h3>Unbound 1.26.1</h3></body>')
        with self.assertRaisesRegex(ValueError, 'sequence'):
            check.parse_releases(source, (1, 25, 2))

    def test_missing_relevant_date_or_malformed_version_fails(self):
        with self.assertRaisesRegex(ValueError, 'publication date'):
            check.parse_releases(download().replace('<dt>Date:</dt><dd>16 September, 2026</dd>', ''), (1, 25, 2))
        with self.assertRaisesRegex(ValueError, 'unrecognized'):
            check.parse_releases(download().replace('Unbound 1.26.1</h3>', 'Unbound 1.26.1-rc1</h3>'), (1, 25, 2))

    def test_upstream_sources_must_agree_and_be_public_release(self):
        self.assertEqual(check.verify_latest_github(github(), (1, 26, 2)), '2026-10-21T08:55:36Z')
        for payload in (github('release-1.26.1'), github(prerelease=True), github(draft=True), github(published_at=None)):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                check.verify_latest_github(payload, (1, 26, 2))


class AdvisoryTests(unittest.TestCase):
    def test_recent_advisory_is_review_signal_not_exploitability(self):
        result = check.parse_advisories(advisory(), (1, 25, 2), {'CVE-2026-81642'})
        self.assertEqual(result, [{'cve': 'CVE-2026-81642', 'date': '2026-09-16',
                                   'affects': 'Unbound up to and including version 1.26.0'}])
        self.assertEqual(check.parse_advisories(advisory(), (1, 26, 1)), [])

    def test_old_disclosure_affecting_current_version_is_not_discarded(self):
        result = check.parse_advisories(advisory(disclosed='2026-07-01',
                                      affects='Unbound up to and including version 1.25.2'), (1, 25, 2))
        self.assertEqual([entry['cve'] for entry in result], ['CVE-2026-81642'])

    def test_conditional_range_is_conservative_and_unknown_grammar_fails(self):
        self.assertTrue(check.affected_version((1, 25, 2),
            'Unbound 1.6.2 up to and including version 1.26.0 compiled and configured for ECS support'))
        self.assertFalse(check.affected_version((1, 25, 2), 'Unbound 1.4.13p2 and earlier versions'))
        self.assertTrue(check.affected_version((1, 4, 13), 'Unbound 1.4.13p2 and earlier versions'))
        with self.assertRaisesRegex(ValueError, 'unrecognized'):
            check.affected_version((1, 25, 2), 'versions except an unclear subset')
        with self.assertRaisesRegex(ValueError, 'unrecognized'):
            check.affected_version((1, 25, 2), 'Unbound up to and including version 1.25.1 and all later versions')
        with self.assertRaisesRegex(ValueError, 'inverted'):
            check.affected_version((1, 25, 2), 'Unbound 1.30.0 up to and including version 1.26.0')

    def test_missing_cve_from_official_advisory_list_fails(self):
        with self.assertRaisesRegex(ValueError, 'omits'):
            check.parse_advisories(advisory(), (1, 25, 2), {'CVE-2026-99999'})

    def test_truncated_duplicate_and_malformed_fields_fail(self):
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            check.parse_advisories(advisory().replace('</body>', ''), (1, 25, 2))
        with self.assertRaisesRegex(ValueError, 'invalid date'):
            check.parse_advisories(advisory(disclosed='2026-99-99'), (1, 25, 2))
        with self.assertRaisesRegex(ValueError, 'canonical'):
            check.parse_advisories(advisory(cve='not-a-cve'), (1, 25, 2))
        two = advisory().replace('</body>', advisory().replace('<html><body>', '').replace('</body></html>', '') + '</body>')
        with self.assertRaisesRegex(ValueError, 'repeats'):
            check.parse_advisories(two, (1, 25, 2))

    def test_updated_date_uses_most_recent_date(self):
        report = check.parse_advisories(advisory(disclosed='2025-10-22 (updated: 2026-11-26)'), (1, 25, 2))
        self.assertEqual(report[0]['date'], '2026-11-26')


class RegistryTests(unittest.TestCase):
    def test_third_party_digest_needs_active_unambiguous_amd64(self):
        result = check.check_image(image(), '1.26.2')
        self.assertEqual(result['tag'], '1.26.2')
        self.assertTrue(result['amd64_digest'].startswith('sha256:'))
        for data in (image(tag='1.26.1'), image(tag_status='inactive'), image(digest='broken'),
                     image(images=[]), image(images=[{'os': 'linux', 'architecture': 'amd64',
                                                     'status': 'inactive', 'digest': 'sha256:' + 'b' * 64}])):
            with self.subTest(data=data), self.assertRaises(ValueError):
                check.check_image(data, '1.26.2')

    def test_cross_origin_and_query_redirect_rejected(self):
        for bad in ('http://www.nlnetlabs.nl/projects/unbound/download/',
                    'https://attacker.example/projects/unbound/download/',
                    check.DOWNLOAD_URL + '?x=1'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                check.validate_url(bad, check.DOWNLOAD_URL)

    def test_fetch_rejects_wrong_redirect_empty_or_oversized_body(self):
        class Response:
            def __init__(self, url, data):
                self.url, self.data = url, data
            def __enter__(self):
                return self
            def __exit__(self, *_):
                return False
            def geturl(self):
                return self.url
            def read(self, amount):
                return self.data[:amount]
        class Opener:
            def __init__(self, result):
                self.result = result
            def open(self, request, timeout):
                self.request, self.timeout = request, timeout
                return self.result
        for response in (Response('https://attacker.example/', b'ok'),
                         Response(check.DOWNLOAD_URL, b''),
                         Response(check.DOWNLOAD_URL, b'a' * (check.MAX_BYTES + 1)),
                         Response(check.DOWNLOAD_URL, b'\x00bad')):
            with self.subTest(url=response.url, size=len(response.data)), self.assertRaises(ValueError):
                check.fetch(check.DOWNLOAD_URL, Opener(response))
        opener = Opener(Response(check.DOWNLOAD_URL, b'ok'))
        self.assertEqual(check.fetch(check.DOWNLOAD_URL, opener), 'ok')
        self.assertEqual(opener.timeout, 20)


class MainTests(unittest.TestCase):
    def run_main(self, values):
        with mock.patch.object(check, 'load_host_checker'), \
             mock.patch.object(check, 'installed_version', return_value=((1, 25, 2), 'unbound-ref')), \
             mock.patch.object(check, 'fetch', side_effect=values), \
             mock.patch.object(sys, 'argv', ['check']), mock.patch('builtins.print') as output:
            status = check.main()
        return status, json.loads(output.call_args.args[0])

    def test_detects_upstream_patch_and_recent_advisory(self):
        status, report = self.run_main([download(), github(), advisory(), image()])
        self.assertEqual(status, 2)
        self.assertTrue(report['attention'])
        self.assertEqual(report['upstream_current'], '1.26.2')
        self.assertEqual(report['third_party_image']['tag'], '1.26.2')
        self.assertTrue(report['third_party_image']['available'])
        self.assertEqual(report['errors'], [])

    def test_missing_registry_tag_is_not_reported_as_available(self):
        error = HTTPError('https://hub.docker.com/', 404, 'missing', {}, io.BytesIO())
        status, report = self.run_main([download(), github(), advisory(), error])
        self.assertEqual(status, 2)
        self.assertEqual(report['third_party_image'], {'tag': '1.26.2', 'available': False})

    def test_source_failure_is_error_and_hides_error_details(self):
        status, report = self.run_main([OSError('do not echo this untrusted text')])
        self.assertEqual(status, 1)
        self.assertEqual(report['errors'], ['release review incomplete: OSError'])
        self.assertNotIn('do not echo', str(report))

    def test_matching_current_release_and_old_advisories_can_report_no_candidate(self):
        latest = ('<html><body><h2>Unbound 1.25.2 (Current version)</h2>'
                  '<dl><dt>Date:</dt><dd>22 July, 2026</dd></dl></body></html>')
        status, report = self.run_main([latest, github('release-1.25.2'), advisory(disclosed='2026-01-01',
                                          affects='Unbound up to and including version 1.25.1')])
        self.assertEqual(status, 0)
        self.assertFalse(report['attention'])
        self.assertIsNone(report['third_party_image'])
        self.assertEqual(report['errors'], [])

    def test_registry_throttling_is_error_not_clean(self):
        error = HTTPError('https://hub.docker.com/', 429, 'too many', {}, io.BytesIO())
        status, report = self.run_main([download(), github(), advisory(), error])
        self.assertEqual(status, 1)
        self.assertEqual(report['errors'], ['release review incomplete: HTTPError'])
        self.assertTrue(report['attention'])

    def test_changed_same_version_digest_fails_after_source_fetch(self):
        with mock.patch.object(check, 'load_host_checker'), \
             mock.patch.object(check, 'installed_version', side_effect=[((1, 25, 2), 'digest-a'), ((1, 25, 2), 'digest-b')]), \
             mock.patch.object(check, 'fetch', side_effect=[download(), github(), advisory(), image()]), \
             mock.patch.object(sys, 'argv', ['check']), mock.patch('builtins.print') as output:
            self.assertEqual(check.main(), 1)
        self.assertEqual(json.loads(output.call_args.args[0])['errors'], ['release review incomplete: ValueError'])


if __name__ == '__main__':
    unittest.main()
