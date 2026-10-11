"""Exercise bundle auditing with real tar files; fixtures are not boot evidence."""
import hashlib
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name('bpf72_bundle.py')
MODULE_COUNT = 376
TIMEOUT_SECONDS = 60
CANDIDATE_RELEASE = '7.2.9-f50-bpf1'
RAMDISK = b'test compressed ramdisk'
MODULE_NAMES = tuple(f'driver_{index:03d}' for index in range(MODULE_COUNT))


def fixture_entries(release):
    metadata = {'ramdisk': 'ramdisk-generic.lz4', 'size': len(RAMDISK),
                'sha256': hashlib.sha256(RAMDISK).hexdigest(), 'modules': 26,
                'init_sha256': '0' * 64}
    return [('kernel.release', release.encode()), ('devices', b'f50 u30air\n'),
            ('features', b'sdcard\nlinux-slot\n'), ('Image', b'wrapped image'),
            ('ramdisk-generic.lz4', RAMDISK),
            ('ramdisk-generic.json', json.dumps(metadata).encode()),
            ('modules.builtin', b'builtin\n'), ('modules.builtin.modinfo', b'info\n')]


def write_bundle(path, entries):
    with tarfile.open(path, 'w:gz') as archive:
        for name, payload in entries:
            entry = tarfile.TarInfo('./' + name)
            entry.size = len(payload)
            archive.addfile(entry, io.BytesIO(payload))
    return path


class BundleAuditTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / 'modules'
        self.source.mkdir()
        self.module_entries = []
        for name in MODULE_NAMES:
            payload = ('ELF fixture: ' + name).encode()
            (self.source / (name + '.ko')).write_bytes(payload)
            self.module_entries.append(('modules/' + name + '.ko', payload))
        self.reference = self.root / 'reference.json'
        self.report = self.root / 'report.json'

    def command(self, operation, bundle):
        arguments = [sys.executable, '-B', str(SCRIPT), operation,
                     '--bundle', str(bundle)]
        if operation == 'verify':
            arguments += ['--reference', str(self.reference), '--module-dir',
                          str(self.source), '--kernel-release', CANDIDATE_RELEASE]
        output = self.reference if operation == 'prepare-reference' else self.report
        return subprocess.run(arguments + ['--output', str(output)],
                              capture_output=True, text=True, timeout=TIMEOUT_SECONDS)

    def prepare(self):
        bundle = write_bundle(self.root / 'official.tgz',
                              fixture_entries('7.2.9') + self.module_entries)
        result = self.command('prepare-reference', bundle)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return bundle

    def verify_entries(self, entries):
        self.prepare()
        return self.command('verify', write_bundle(self.root / 'candidate.tgz', entries))

    def assert_failure(self, result, message):
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        report = json.loads(self.report.read_text())
        self.assertEqual(report['status'], 'FAIL')
        self.assertIn(message, report['error'])

    def test_prepares_sorted_official_manifest_and_bundle_hash(self):
        bundle = self.prepare()
        manifest = json.loads(self.reference.read_text())
        self.assertEqual(manifest['module_names'], list(MODULE_NAMES))
        self.assertEqual(manifest['reference_sha256'],
                         hashlib.sha256(bundle.read_bytes()).hexdigest())
        self.assertEqual(manifest['module_count'], MODULE_COUNT)

    def test_verifies_all_packaged_module_bytes_against_source(self):
        result = self.verify_entries(fixture_entries(CANDIDATE_RELEASE) + self.module_entries)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(self.report.read_text())
        self.assertEqual(report['status'], 'PASS')
        self.assertEqual(report['module_count'], MODULE_COUNT)
        self.assertFalse(report['runtime_boot_verified'])
        self.assertEqual(len(report['modules']), MODULE_COUNT)

    def test_rejects_reference_manifest_missing_a_module(self):
        self.prepare()
        manifest = json.loads(self.reference.read_text())
        manifest['module_names'].pop()
        self.reference.write_text(json.dumps(manifest))
        bundle = write_bundle(self.root / 'candidate.tgz',
                              fixture_entries(CANDIDATE_RELEASE) + self.module_entries)
        self.assert_failure(self.command('verify', bundle), '376')

    def test_rejects_duplicate_archive_path(self):
        entries = fixture_entries(CANDIDATE_RELEASE) + self.module_entries
        self.assert_failure(self.verify_entries(entries + [self.module_entries[0]]), 'Duplicate')

    def test_rejects_hyphen_underscore_alias_collision(self):
        entries = fixture_entries(CANDIDATE_RELEASE) + self.module_entries
        entries[-1] = ('modules/driver-000.ko', b'alias')
        self.assert_failure(self.verify_entries(entries), 'alias')

    def test_rejects_wrong_candidate_kernel_release(self):
        result = self.verify_entries(fixture_entries('7.2.9') + self.module_entries)
        self.assert_failure(result, 'kernel.release')

    def test_rejects_changed_candidate_module_bytes(self):
        entries = fixture_entries(CANDIDATE_RELEASE) + self.module_entries
        entries[-1] = (entries[-1][0], b'corrupted module')
        self.assert_failure(self.verify_entries(entries), 'SHA256')

    def test_rejects_missing_module_in_official_bundle(self):
        bundle = write_bundle(self.root / 'official.tgz',
                              fixture_entries('7.2.9') + self.module_entries[:-1])
        result = self.command('prepare-reference', bundle)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('376', json.loads(self.reference.read_text())['error'])

    def test_rejects_wrong_official_version(self):
        bundle = write_bundle(self.root / 'official.tgz',
                              fixture_entries('7.2.8') + self.module_entries)
        result = self.command('prepare-reference', bundle)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('kernel.release', json.loads(self.reference.read_text())['error'])

    def test_rejects_missing_device_or_feature(self):
        for name, value in [('devices', b'u30air'), ('features', b'sdcard')]:
            with self.subTest(name=name):
                entries = [(key, value if key == name else data)
                           for key, data in fixture_entries(CANDIDATE_RELEASE)]
                self.assert_failure(self.verify_entries(entries + self.module_entries), name)

    def test_rejects_empty_image_or_ramdisk(self):
        for name in ['Image', 'ramdisk-generic.lz4']:
            with self.subTest(name=name):
                entries = [(key, b'' if key == name else data)
                           for key, data in fixture_entries(CANDIDATE_RELEASE)]
                self.assert_failure(self.verify_entries(entries + self.module_entries), 'empty')

    def test_rejects_ramdisk_metadata_hash_mismatch(self):
        entries = [(key, b'damaged ramdisk' if key == 'ramdisk-generic.lz4' else data)
                   for key, data in fixture_entries(CANDIDATE_RELEASE)]
        self.assert_failure(self.verify_entries(entries + self.module_entries), 'ramdisk')

    def test_rejects_extra_source_module(self):
        self.prepare()
        (self.source / 'unexpected.ko').write_bytes(b'extra')
        bundle = write_bundle(self.root / 'candidate.tgz',
                              fixture_entries(CANDIDATE_RELEASE) + self.module_entries)
        self.assert_failure(self.command('verify', bundle), 'module')


if __name__ == '__main__':
    unittest.main()
