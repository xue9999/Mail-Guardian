"""Pure authorization tests: no VPS, package, mailbox or filesystem changes."""

from copy import deepcopy
import unittest

import pre_mutation_recovery as recovery


WORKER = "mail-guardian@pilot.service"
BACKUP = "mail-guardian-backup@pilot.service"
INVENTORY = {
    "docker-ce": "5:29.9.2-1~ubuntu.26.04~resolute",
    "docker-ce-cli": "5:29.9.2-1~ubuntu.26.04~resolute",
    "libc6:amd64": "2.43-0ubuntu1",
}
CONTAINERS = {
    service: {"image_id": "sha256:" + digit * 64,
              "mounts_sha256": "a" * 64, "ports_sha256": "b" * 64}
    for service, digit in (("redis", "1"), ("rspamd", "2"), ("unbound", "3"))
}


class PreMutationAuthorizationTests(unittest.TestCase):
    def setUp(self):
        # Full journal authenticity and marker binding are prechecked by the
        # caller. This pure function decides whether the recorded and observed
        # states are consistent with narrowly scoped pre-mutation recovery.
        self.record = {"phase": "fenced", "plan": {
            "inventory": deepcopy(INVENTORY), "containers": deepcopy(CONTAINERS)}}
        self.inventory = deepcopy(INVENTORY)
        self.containers = deepcopy(CONTAINERS)
        self.updater_state = "failed"
        self.workers = {WORKER: "inactive", BACKUP: "inactive"}
        self.dpkg_clean = True

    def authorize(self):
        return recovery.authorize(self.record, self.inventory, self.containers,
                                  self.updater_state, self.workers, self.dpkg_clean)

    def rejected(self):
        with self.assertRaises(recovery.RecoveryError):
            self.authorize()

    def test_only_known_pre_mutation_phases_are_allowed(self):
        for phase in ("prepared", "fence_creating", "fenced", "pre_mutation_clear_intent"):
            with self.subTest(phase=phase):
                self.record["phase"] = phase
                self.assertIsNone(self.authorize())
        for phase in ("mutation_pending", "verified", "unfence_intent",
                      "completed", "recovery_required", "pre_mutation_recovered",
                      "aborted", "unknown", "", None, [], {}):
            with self.subTest(phase=phase):
                self.record["phase"] = phase
                self.rejected()

    def test_updater_must_be_definitively_inactive(self):
        for state in ("inactive", "failed"):
            with self.subTest(state=state):
                self.updater_state = state
                self.assertIsNone(self.authorize())
        for state in ("active", "activating", "deactivating", "reloading",
                      "unknown", "not-found", "", None, False, [], {}):
            with self.subTest(state=state):
                self.updater_state = state
                self.rejected()

    def test_both_exact_worker_units_must_be_inactive(self):
        self.assertIsNone(self.authorize())
        # A failed worker may have unresolved mail or backup work. Its state
        # alone does not prove it failed solely because of the update fence.
        for state in ("active", "failed", "activating", "deactivating", "reloading", "unknown", "", None, [], {}):
            with self.subTest(state=state):
                self.workers = {WORKER: state, BACKUP: "inactive"}
                self.rejected()
                self.workers = {WORKER: "inactive", BACKUP: state}
                self.rejected()
        for invalid in ({}, {WORKER: "inactive"}, {BACKUP: "inactive"},
                        {WORKER: "inactive", BACKUP: "inactive", "other.service": "inactive"},
                        None, [], "inactive"):
            with self.subTest(workers=invalid):
                self.workers = invalid
                self.rejected()

    def test_package_inventory_must_match_exactly(self):
        for invalid in (
            {**INVENTORY, "docker-ce": "5:29.9.3-1~ubuntu.26.04~resolute"},
            {key: value for key, value in INVENTORY.items() if key != "docker-ce"},
            {**INVENTORY, "unexpected-package": "1.0"},
            {}, None, [], "not-a-dict",
        ):
            with self.subTest(inventory=invalid):
                self.inventory = invalid
                self.rejected()
        self.inventory = dict(reversed(list(INVENTORY.items())))
        self.assertIsNone(self.authorize())

    def test_every_container_identity_mount_and_port_must_match(self):
        for service in CONTAINERS:
            for field in ("image_id", "mounts_sha256", "ports_sha256"):
                with self.subTest(service=service, field=field):
                    self.containers = deepcopy(CONTAINERS)
                    self.containers[service][field] = "different"
                    self.rejected()
        for invalid in ({}, {"redis": CONTAINERS["redis"]},
                        {**CONTAINERS, "extra": CONTAINERS["redis"]},
                        None, [], "not-a-dict"):
            with self.subTest(containers=invalid):
                self.containers = invalid
                self.rejected()

    def test_dpkg_audit_must_be_explicit_boolean_true(self):
        for invalid in (False, None, 0, 1, "true", [], {}):
            with self.subTest(dpkg_clean=invalid):
                self.dpkg_clean = invalid
                self.rejected()

    def test_malformed_record_fails_closed(self):
        for invalid in (None, {}, [], "bad", {"phase": "fenced"},
                        {"phase": "fenced", "plan": None},
                        {"phase": "fenced", "plan": {}},
                        {"phase": "fenced", "plan": {"inventory": INVENTORY}},
                        {"phase": "fenced", "plan": {"containers": CONTAINERS}}):
            with self.subTest(record=invalid):
                self.record = invalid
                self.rejected()


if __name__ == "__main__":
    unittest.main()
