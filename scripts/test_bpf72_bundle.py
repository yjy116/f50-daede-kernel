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
from types import SimpleNamespace
from unittest.mock import patch

import bpf72_bundle as audit
from validate_kernel import ELF_HEADER, SECTION_HEADER, EM_AARCH64, ET_REL


SCRIPT = Path(__file__).with_name('bpf72_bundle.py')
MODULE_COUNT = audit.CANDIDATE_MODULE_COUNT
TIMEOUT_SECONDS = 60
CANDIDATE_RELEASE = '7.2.9-f50-bpf1'
RAMDISK = b'test compressed ramdisk'
ORDINARY_NAMES = tuple(f'driver_{index:03d}' for index in range(373))
MODULE_NAMES = tuple(sorted(ORDINARY_NAMES + tuple(audit.REFERENCE_CASE_COLLISIONS)
                            + tuple(audit.REFERENCE_CASE_COLLISIONS.values())))


def module_fixture(name):
    """Minimal real ELF sections for identity tests, not executable module code."""
    strings = b'\0.shstrtab\0.modinfo\0'
    info = b'name=' + name.encode() + b'\0'
    string_offset = ELF_HEADER.size
    info_offset = string_offset + len(strings)
    table_offset = info_offset + len(info)
    ident = b'\x7fELF\x02\x01\x01' + bytes(9)
    header = ELF_HEADER.pack(ident, ET_REL, EM_AARCH64, 1, 0, 0, table_offset,
                             0, ELF_HEADER.size, 0, 0, SECTION_HEADER.size, 3, 1)
    null = SECTION_HEADER.pack(*([0] * 10))
    strtab = SECTION_HEADER.pack(1, 3, 0, 0, string_offset, len(strings), 0, 0, 1, 0)
    modinfo = SECTION_HEADER.pack(11, 1, 0, 0, info_offset, len(info), 0, 0, 1, 0)
    return header + strings + info + null + strtab + modinfo


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
        self.sources = {}
        for name in MODULE_NAMES:
            payload = module_fixture(name)
            # NTFS cannot store both xt_DSCP.ko and xt_dscp.ko: preserve the logical
            # inventory in tar, and map source reads to distinct encoded paths.
            target = self.source / (name.encode().hex() + '.ko')
            target.write_bytes(payload)
            self.sources[name] = target
            self.module_entries.append(('modules/' + name + '.ko', payload))
        self.reference_entries = [('modules/' + name + '.ko', module_fixture(
            audit.REFERENCE_CASE_COLLISIONS.get(name, name)))
            for name in sorted(ORDINARY_NAMES + tuple(audit.REFERENCE_CASE_COLLISIONS))]
        self.reference = self.root / 'reference.json'
        self.report = self.root / 'report.json'

    def command(self, operation, bundle):
        if operation == 'verify':
            return self.verify_command(bundle)
        arguments = [sys.executable, '-B', str(SCRIPT), operation,
                     '--bundle', str(bundle)]
        output = self.reference if operation == 'prepare-reference' else self.report
        return subprocess.run(arguments + ['--output', str(output)],
                              capture_output=True, text=True, timeout=TIMEOUT_SECONDS)

    def verify_command(self, bundle):
        options = SimpleNamespace(bundle=bundle, reference=self.reference,
                                  module_dir=self.source, kernel_release=CANDIDATE_RELEASE)
        with patch.object(audit, 'source_modules', return_value=self.sources):
            try:
                report = audit.verify(options)
            except ValueError as error:
                report = {'status': 'FAIL', 'error': str(error)}
        self.report.write_text(json.dumps(report))
        return SimpleNamespace(returncode=int(report['status'] != 'PASS'),
                               stdout=json.dumps(report), stderr='')

    def prepare(self):
        bundle = write_bundle(self.root / 'official.tgz',
                              fixture_entries('7.2.9') + self.reference_entries)
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
        self.assertEqual(manifest['reference_module_count'], 376)
        self.assertEqual(len(manifest['reference_case_collisions']), 3)

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
        self.assert_failure(self.command('verify', bundle), '379')

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
                              fixture_entries('7.2.9') + self.reference_entries[:-1])
        result = self.command('prepare-reference', bundle)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('376', json.loads(self.reference.read_text())['error'])

    def test_rejects_wrong_official_version(self):
        bundle = write_bundle(self.root / 'official.tgz',
                              fixture_entries('7.2.8') + self.reference_entries)
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
        self.sources['unexpected'] = self.source / 'unexpected.ko'
        bundle = write_bundle(self.root / 'candidate.tgz',
                              fixture_entries(CANDIDATE_RELEASE) + self.module_entries)
        self.assert_failure(self.command('verify', bundle), 'module')

    def test_rejects_reference_payload_with_unrecognized_identity(self):
        entries = list(self.reference_entries)
        entries[-1] = (entries[-1][0], module_fixture('unexpected'))
        bundle = write_bundle(self.root / 'official.tgz', fixture_entries('7.2.9') + entries)
        result = self.command('prepare-reference', bundle)
        self.assertEqual(result.returncode, 1)
        self.assertIn('identity mismatch', json.loads(self.reference.read_text())['error'])

    def test_rejects_candidate_repeating_official_case_collision(self):
        wrong = module_fixture('xt_DSCP')
        self.sources['xt_dscp'].write_bytes(wrong)
        entries = [(name, wrong if name == 'modules/xt_dscp.ko' else data)
                   for name, data in self.module_entries]
        self.assert_failure(self.verify_entries(fixture_entries(CANDIDATE_RELEASE) + entries),
                            'internal name mismatch')

    def test_rejects_arbitrary_extra_even_when_repaired_count_is_preserved(self):
        entries = list(self.module_entries)
        entries[-1] = ('modules/unexpected.ko', module_fixture('unexpected'))
        self.assert_failure(self.verify_entries(fixture_entries(CANDIDATE_RELEASE) + entries),
                            'inventory changed')

    def test_rejects_forged_case_collision_manifest(self):
        self.prepare()
        manifest = json.loads(self.reference.read_text())
        manifest['reference_case_collisions'][0]['internal_name'] = 'unexpected'
        self.reference.write_text(json.dumps(manifest))
        bundle = write_bundle(self.root / 'candidate.tgz',
                              fixture_entries(CANDIDATE_RELEASE) + self.module_entries)
        self.assert_failure(self.command('verify', bundle), 'case-collision evidence')


if __name__ == '__main__':
    unittest.main()
