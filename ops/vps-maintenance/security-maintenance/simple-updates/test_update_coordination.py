"""A reboot must not let a sibling updater bypass durable recovery state."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import guardian_images as images

spec = importlib.util.spec_from_file_location('coordinated_docker_updater', Path(__file__).parent / 'docker/updater.py')
docker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(docker)


class DurableCoordinationTests(unittest.TestCase):
    def test_docker_defers_foreign_journal_even_without_migration_marker(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            foreign = root / 'ubuntu-pending'
            foreign.write_text('{}')
            with mock.patch.multiple(docker, FOREIGN_PENDING=(foreign,), PENDING=root / 'docker-pending'):
                self.assertTrue(docker.foreign_update_pending())
                with self.assertRaisesRegex(docker.e.UpdateError, 'pending recovery'):
                    docker.foreign_update_pending(inspection=True)

    def test_two_durable_transactions_require_manual_resolution(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            foreign, own = root / 'foreign', root / 'own'
            foreign.write_text('{}')
            own.write_text('{}')
            with mock.patch.multiple(docker, FOREIGN_PENDING=(foreign,), PENDING=own):
                with self.assertRaisesRegex(docker.e.UpdateError, 'pending recovery'):
                    docker.foreign_update_pending()

    def test_image_discovery_and_recovery_do_not_run_past_foreign_journal(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            foreign = root / 'ubuntu-pending'
            foreign.write_text('{}')
            with mock.patch.multiple(images, STATE=root, FOREIGN_PENDING=(foreign,), JOURNAL=root / 'own'), \
                    mock.patch.object(images, 'run') as run, \
                    mock.patch.object(images.image_discovery, 'discover') as discover:
                images.execute()
                images.execute(recovery_only=True)
                run.assert_not_called()
                discover.assert_not_called()
                with self.assertRaisesRegex(RuntimeError, 'pending recovery'):
                    images.execute(no_update_only=True)

    def test_dangling_foreign_marker_also_blocks(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            foreign = root / 'dangling'
            foreign.symlink_to(root / 'absent')
            with mock.patch.multiple(docker, FOREIGN_PENDING=(foreign,), PENDING=root / 'own'):
                self.assertTrue(docker.foreign_update_pending())


if __name__ == '__main__':
    unittest.main()
