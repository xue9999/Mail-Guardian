import hashlib
import json
from pathlib import Path
import socket
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import fenced_backup as b


class FencedBackupTests(unittest.TestCase):
    def test_volume_capture_excludes_socket_and_rejects_links(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / 'vol'
            root.mkdir()
            (root / 'state').write_text('model')
            sock = socket.socket(socket.AF_UNIX)
            try:
                sock.bind(str(root / 'socket'))
                output = Path(raw) / 'state.tgz'
                b.volume_tar(root, output)
                with tarfile.open(output) as archive:
                    self.assertEqual(archive.getnames(), ['state'])
                (root / 'bad').symlink_to('/etc/passwd')
                with self.assertRaisesRegex(RuntimeError, 'special file'):
                    b.volume_tar(root, Path(raw) / 'bad.tgz')
            finally:
                sock.close()

    def test_backup_includes_model_and_volumes_and_checks_fence(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, state, backups, current, volume = [root / x for x in ('base', 'state', 'backups', 'release', 'volumes')]
            (base / 'pilot').mkdir(parents=True)
            (base / 'pilot/backup-recipient').write_text('age1' + 'a' * 58 + '\n')
            (backups / 'pilot').mkdir(parents=True)
            current.mkdir()
            (current / 'guardian-recovery').touch()
            for name in b.VOLUMES.values():
                path = volume / name / '_data'
                path.mkdir(parents=True)
                (path / 'state').write_text(name)
            captured = {}
            def capture(instance, staging, maintenance):
                (staging / 'configuration/credentials').mkdir(parents=True)
                (staging / 'configuration/config.toml').write_text('x')
                (staging / 'configuration/credentials/archive-identity').write_text('secret')
                (staging / 'guardian.db').write_text('db')
                (staging / 'archive').mkdir()
                return 42
            backup = SimpleNamespace(BASE=base, STATE=state, BACKUPS=backups, CURRENT=current,
                                     MAX_TOTAL=100, MAX_FILE=100, capture=capture)
            def trusted(path, **kwargs): return Path(path)
            def command(args, timeout):
                if args[1] == 'inspect-snapshot':
                    config = Path(args[args.index('--config') + 1])
                    self.assertEqual(config.stat().st_mode & 0o077, 0)
                    return b'{}'
                if args[1] == 'relocate-snapshot':
                    Path(args[args.index('--database') + 1]).touch()
                    return b'{}'
                source = Path(args[args.index('--source') + 1])
                captured['names'] = {x.name for x in source.iterdir()}
                data = b'encrypted-fixture'
                destination = Path(args[args.index('--destination') + 1])
                destination.write_bytes(data)
                destination.chmod(0o600)
                return json.dumps({'sha256': hashlib.sha256(data).hexdigest()}).encode()
            maintenance = SimpleNamespace(trusted_path=trusted, run=command)
            dispatcher = SimpleNamespace(dispatch=lambda op: b'REDIS0012' + b'fixture-data')
            count = []
            with mock.patch.object(b, 'VOLUME_ROOT', volume):
                result = b.save_backup(backup, maintenance, dispatcher, lambda: count.append(True))
            self.assertGreaterEqual(len(count), 4)
            self.assertTrue({'redis.rdb', 'rspamd-volume.tar.gz', 'unbound-volume.tar.gz'} <= captured['names'])
            self.assertTrue((backups / 'pilot' / (result['name'] + '.sha256')).is_file())


if __name__ == '__main__':
    unittest.main()
