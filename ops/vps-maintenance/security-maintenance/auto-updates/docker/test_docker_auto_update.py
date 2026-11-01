"""Independent fail-closed checks for automatic Docker update decisions."""

import importlib.util
from pathlib import Path
import unittest
from unittest import mock

MODULE_PATH = Path(__file__).with_name("docker_auto_update.py")
SPEC = importlib.util.spec_from_file_location("docker_auto_update", MODULE_PATH)
updater = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(updater)


class PatchPolicyTests(unittest.TestCase):
    def check(self, old, new, expected, is_newer=True):
        with mock.patch.object(updater, "version_is_newer", return_value=is_newer):
            self.assertEqual(updater.patch_update_allowed(old, new), expected)

    def test_patch_with_debian_epoch_and_revision(self):
        self.check("5:29.9.1-1~ubuntu.26.04~resolute",
                   "5:29.9.2-1~ubuntu.26.04~resolute", True)

    def test_same_upstream_debian_package_revision(self):
        self.check("2.4.2-2~ubuntu.26.04~resolute",
                   "2.4.2-3~ubuntu.26.04~resolute", True)

    def test_minor_major_and_epoch_changes_are_not_automatic(self):
        old = "5:29.9.2-1~ubuntu.26.04~resolute"
        for candidate in ("5:29.10.0-1~ubuntu.26.04~resolute",
                          "5:30.0.0-1~ubuntu.26.04~resolute",
                          "6:29.9.3-1~ubuntu.26.04~resolute"):
            with self.subTest(candidate=candidate):
                self.check(old, candidate, False)

    def test_never_accept_a_downgrade_or_equal_version(self):
        self.check("5:29.9.2-1~ubuntu.26.04~resolute",
                   "5:29.9.1-1~ubuntu.26.04~resolute", False, is_newer=False)
        self.check("2.4.2-2~ubuntu.26.04~resolute",
                   "2.4.2-2~ubuntu.26.04~resolute", False, is_newer=False)

    def test_prerelease_and_malformed_versions_are_not_automatic(self):
        for candidate in ("5:29.9.3~rc1-1~ubuntu.26.04~resolute",
                          "5:29.9.3-1~ubuntu.26.04~resolute~rc1",
                          "5:29.9.3-1~ubuntu.26.04~resolute+beta.1",
                          "5:29.9.3-1~ubuntu.26.04~resolute~DEV1",
                          "garbage", "29.9"):
            with self.subTest(candidate=candidate):
                self.check("5:29.9.2-1~ubuntu.26.04~resolute", candidate, False)


class SimulationPolicyTests(unittest.TestCase):
    def setUp(self):
        self.expected = {
            "docker-ce": "5:29.9.2-1~ubuntu.26.04~resolute",
            "docker-ce-cli": "5:29.9.2-1~ubuntu.26.04~resolute",
        }
        self.line_a = ("Inst docker-ce [5:29.9.1-1~ubuntu.26.04~resolute] "
                       "(5:29.9.2-1~ubuntu.26.04~resolute Docker:resolute [amd64])")
        self.line_b = ("Inst docker-ce-cli [5:29.9.1-1~ubuntu.26.04~resolute] "
                       "(5:29.9.2-1~ubuntu.26.04~resolute Docker:resolute [amd64])")
        self.conf_a = "Conf docker-ce (5:29.9.2-1~ubuntu.26.04~resolute Docker:resolute [amd64])"
        self.conf_b = "Conf docker-ce-cli (5:29.9.2-1~ubuntu.26.04~resolute Docker:resolute [amd64])"
        self.success = "\n".join((self.line_a, self.line_b, self.conf_a, self.conf_b))

    def test_exact_installs_only_are_safe(self):
        output = "Reading package lists...\n" + self.success + "\n"
        self.assertTrue(updater.simulation_is_safe(output, self.expected))

    def test_real_docker_ce_label_with_space_is_accepted(self):
        output = self.success.replace("Docker:resolute", "Docker CE:resolute")
        self.assertTrue(updater.simulation_is_safe(output, self.expected))

    def test_missing_expected_target_is_rejected(self):
        self.assertFalse(updater.simulation_is_safe(self.line_a + "\n", self.expected))

    def test_duplicate_install_is_rejected(self):
        self.assertFalse(updater.simulation_is_safe(self.success + "\n" + self.line_a, self.expected))

    def test_extra_dependency_is_rejected(self):
        output = self.success + "\nInst surprise [1] (2 Ubuntu:resolute [amd64])\n"
        self.assertFalse(updater.simulation_is_safe(output, self.expected))

    def test_removals_are_rejected(self):
        output = self.success + "\nRemv redis [1.0]\n"
        self.assertFalse(updater.simulation_is_safe(output, self.expected))

    def test_transaction_actions_cannot_be_hidden_by_whitespace(self):
        for action in ("Remv\tredis [1.0]", "  Remv redis [1.0]", "Purg\tredis [1.0]",
                       "Inst\tsurprise [1] (2 Ubuntu:resolute [amd64])"):
            with self.subTest(action=action):
                output = self.success + "\n" + action + "\n"
                self.assertFalse(updater.simulation_is_safe(output, self.expected))

    def test_configuring_unrelated_packages_is_rejected(self):
        output = self.success + "\nConf unrelated (1.0 Ubuntu:resolute [amd64])\n"
        self.assertFalse(updater.simulation_is_safe(output, self.expected))

    def test_configuring_expected_packages_is_accepted(self):
        self.assertTrue(updater.simulation_is_safe(self.success, self.expected))

    def test_configuring_expected_package_at_wrong_version_is_rejected(self):
        output = self.success.replace(self.conf_a, self.conf_a.replace("29.9.2", "29.9.3"))
        self.assertFalse(updater.simulation_is_safe(output, self.expected))

    def test_missing_configure_is_rejected(self):
        self.assertFalse(updater.simulation_is_safe(self.success.replace(self.conf_b, ""), self.expected))

    def test_truncated_configure_is_rejected(self):
        self.assertFalse(updater.simulation_is_safe(self.success.replace(self.conf_b, "Conf docker-ce-cli"), self.expected))

    def test_duplicate_configure_is_rejected(self):
        self.assertFalse(updater.simulation_is_safe(self.success + "\n" + self.conf_b, self.expected))

    def test_candidate_version_mismatch_is_rejected(self):
        altered = self.line_a.replace("(5:29.9.2-", "(5:29.9.3-")
        self.assertFalse(updater.simulation_is_safe(self.success.replace(self.line_a, altered), self.expected))

    def test_target_without_installed_version_is_rejected(self):
        fresh = ("Inst docker-ce (5:29.9.2-1~ubuntu.26.04~resolute "
                 "Docker:resolute [amd64])")
        self.assertFalse(updater.simulation_is_safe(self.success.replace(self.line_a, fresh), self.expected))

    def test_unexpected_package_origin_is_rejected(self):
        altered = self.line_a.replace("Docker:resolute", "Untrusted:resolute")
        self.assertFalse(updater.simulation_is_safe(self.success.replace(self.line_a, altered), self.expected))

    def test_malformed_install_line_is_rejected(self):
        output = self.success + "\nInst malformed\n"
        self.assertFalse(updater.simulation_is_safe(output, self.expected))

    def test_empty_simulation_is_rejected_when_targets_expected(self):
        self.assertFalse(updater.simulation_is_safe("Reading package lists...\n", self.expected))


if __name__ == "__main__":
    unittest.main()
