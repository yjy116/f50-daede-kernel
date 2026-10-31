"""Focused synthetic tests; reuse the existing archive/SQLite fixture builder."""
import argparse
import hashlib
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import final_snapshot_metadata as tool

FIXTURE = tool.module('existing_snapshot_fixture', tool.LEGACY / 'test_verify_snapshot.py')


def public_key():
    key = Ed25519PrivateKey.generate().public_key()
    return key.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)


class FinalSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='f50-metadata-test-')
        self.addCleanup(self.temporary.cleanup)
        self.parent = Path(self.temporary.name).resolve()
        self.root = self.parent / 'capture'
        self.root.mkdir()
        self.key = public_key() + b' temporary-test-only'
        self.other = public_key() + b' preserve-this-authorization'
        self.authorization = self.other + b'\r\n# retained comment\n' + self.key + b'\n'
        self.pub = self.parent / 'temporary.pub'
        self.pub.write_bytes(self.key + b'\n')
        self.fixture = FIXTURE.Snapshot(self.root)
        self.configure_fixture()

    def configure_fixture(self):
        old = 'lib/modules/test/module.ko'
        new = 'lib/modules/' + tool.KERNEL_VERSION + '/module.ko'
        self.fixture.items[new] = self.fixture.items.pop(old)
        paths = self.fixture.items[FIXTURE.PRESERVE]['content'].replace(
            b'lib/modules/test', ('lib/modules/' + tool.KERNEL_VERSION).encode())
        self.fixture.file(FIXTURE.PRESERVE, paths)
        self.fixture.file(tool.AUTH_PATH, self.authorization, mode='0600', uid=0, gid=0)
        self.fixture.file(tool.PROFILE_SHA_PATH,
                          (tool.KERNEL_SHA + '  ' + tool.BUNDLE_DEVICE_PATH + '\n').encode())
        self.fixture.save()
        for name in ('metadata.json', 'files.sha256', 'links.tsv', 'SHA256SUMS', 'fixture.db'):
            (self.root / name).unlink()
        (self.root / 'kernel.txt').write_text(tool.KERNEL_VERSION + '\n')
        (self.root / 'image-version.txt').write_text('v2026.10.30.1\n')
        (self.root / 'preserve-paths.txt').write_bytes(paths)
        self.raw_hashes = ''.join(f'{tool.VERIFY.file_hash(self.root / n)}  {n}\n'
                                  for n in tool.VERIFY.ARCHIVES)
        (self.root / 'device-archives.sha256').write_text(self.raw_hashes, newline='\n')

    def options(self, count=1):
        return argparse.Namespace(kernel=tool.BASE / 'official' / tool.KERNEL_NAME,
                                  expected_key_count=count)

    def test_complete_finalize_and_peer_readback(self):
        self.assertEqual(tool.public_line(self.pub), self.key)
        sanitation = tool.prepare(self.root, self.options(), self.key)
        self.assertEqual(sanitation['removed_task_keys'], 1)
        self.assertEqual(tool.archived_file(self.root, tool.AUTH_PATH),
                         self.other + b'\r\n# retained comment\n')
        self.assertEqual((self.root / 'capture-device-archives.sha256').read_text(), self.raw_hashes)
        self.assertIn(tool.AUTH_PATH + '\t600\t0\t0\n',
                      (self.root / 'restore-metadata.tsv').read_text())
        self.assertFalse((self.root / 'INCOMPLETE').exists())
        names = set(tool.VERIFY.sha_manifest(self.root / 'SHA256SUMS')) | {'SHA256SUMS'}
        peer = self.parent / 'device-readback.sha256'
        peer.write_text(''.join(f'{tool.VERIFY.file_hash(self.root / n)}  {n}\n' for n in sorted(names)))
        self.assertEqual(tool.validate(self.root, self.key, peer)['peer_sha256'], 'PASS')
        data = peer.read_text()
        peer.write_text(('0' if data[0] != '0' else '1') + data[1:])
        with self.assertRaisesRegex(tool.VERIFY.SnapshotError, 'readback SHA'):
            tool.check_peer(self.root, peer)

    def test_exact_count_failure_keeps_original_capture(self):
        before = tool.VERIFY.file_hash(self.root / 'settings.tar.gz')
        with self.assertRaisesRegex(tool.VERIFY.SnapshotError, 'count differs'):
            tool.prepare(self.root, self.options(0), self.key)
        self.assertEqual(tool.VERIFY.file_hash(self.root / 'settings.tar.gz'), before)
        self.assertFalse((self.root / 'metadata.json').exists())

    def test_capture_download_mismatch_is_rejected(self):
        (self.root / 'device-archives.sha256').write_text(
            self.raw_hashes.replace(self.raw_hashes[:64], '0' * 64, 1))
        with self.assertRaisesRegex(tool.VERIFY.SnapshotError, 'differs from the device'):
            tool.check_capture_hashes(self.root)

    def test_wrong_running_kernel_is_rejected(self):
        (self.root / 'kernel.txt').write_text('7.2.9-f50-bpf1\n')
        with self.assertRaisesRegex(tool.VERIFY.SnapshotError, 'official 7.2.13'):
            tool.check_release(self.root, self.options().kernel)

    def test_already_revoked_key_explicit_zero_count(self):
        tool.rewrite_authorizations((self.root, self.key, 1))
        original = tool.inventory(self.root / 'settings.tar.gz')
        result = tool.rewrite_authorizations((self.root, self.key, 0))
        self.assertEqual(result['removed_task_keys'], 0)
        self.assertEqual(tool.inventory(self.root / 'settings.tar.gz'), original)


if __name__ == '__main__':
    unittest.main()
