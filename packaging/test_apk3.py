"""Reader boundary checks and exact script serialization, without installing anything."""
import tempfile
import unittest
from pathlib import Path

from apk3 import INFO_FIELDS, acl, blocks, decode, dependency, info_values, member_record, safe_path, verify_data
from repack import package_arguments


class ReaderTests(unittest.TestCase):
    def test_unsafe_member_paths_are_rejected(self):
        for path in ('/etc/passwd', '../secret', 'etc/../secret', 'etc//file',
                     'etc\\file', 'etc/./file', 'etc/\0file', ''):
            with self.subTest(path=path), self.assertRaises(ValueError):
                safe_path(path)
        self.assertEqual(safe_path('', root=True), '')
        self.assertEqual(safe_path('etc/config/daed'), 'etc/config/daed')

    def test_truncated_value_and_cyclic_array_are_rejected(self):
        with self.assertRaises(ValueError):
            decode(b'\0', 0x20000000)
        cyclic = b'\x02\0\0\0\0\0\0\xe0'
        with self.assertRaises(ValueError):
            decode(cyclic, 0xe0000000)

    def test_truncated_block_is_rejected(self):
        with self.assertRaises(ValueError):
            list(blocks(b'ADB.pckg\xff\xff\xff\x7f'))

    def test_unreviewed_acl_and_dependency_formats_fail(self):
        with self.assertRaises(ValueError):
            acl([None, 493, b'user', b'root'])
        with self.assertRaises(ValueError):
            dependency([None, b'libc', b'1', 4])
        self.assertEqual(dependency([None, b'daed', b'1_p1-r1']), 'daed=1_p1-r1')

    def test_script_bytes_and_dependency_arguments_are_exact(self):
        body = b'#!/bin/sh\n# preserve newline and bytes\nexit 0\n'
        info = {'name': 'daed', 'hashes': 'derived', 'installed-size': 123,
                'depends': ['libc', 'daed=1_p1-r1']}
        with tempfile.TemporaryDirectory() as directory:
            args = package_arguments(info, {'post-install': body}, Path(directory))
            self.assertIn('depends:libc daed=1_p1-r1', args)
            self.assertFalse(any('installed-size:' in item or 'hashes:' in item for item in args))
            self.assertEqual((Path(directory) / 'scripts/post-install').read_bytes(), body)

    def test_tags_array_is_preserved_and_serialized_as_apk_tokens(self):
        values = [None] * (len(INFO_FIELDS) + 1)
        values[INFO_FIELDS.index('tags') + 1] = [None, b'openwrt:abiversion=3']
        info = info_values(values)
        self.assertEqual(info, {'tags': ['openwrt:abiversion=3']})
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(package_arguments(info, {}, Path(directory)),
                             ['--info', 'tags:openwrt:abiversion=3'])
        for invalid in ([None, [None, b'nested']], [None, 123], [None, b'a b']):
            values[-1] = invalid
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                info_values(values)

    def test_symlink_metadata_is_exact_without_a_data_block(self):
        member = [None, b'zerotier-cli', [None, 511, b'root', b'root'],
                  12, 1757613129, None, b'\x00\xa0zerotier-one']
        record = member_record(member)
        self.assertEqual(record['type'], 'symlink')
        self.assertEqual(record['target'], 'zerotier-one')
        self.assertEqual(record['target_blob_hex'], '00a07a65726f746965722d6f6e65')
        self.assertEqual(record['mode'], 511)
        self.assertEqual(verify_data([], ({'usr/bin/zerotier-cli': record}, {(1, 1): 'usr/bin/zerotier-cli'})), {})

    def test_link_with_wrong_size_hash_device_type_or_unsafe_target_fails(self):
        base = [None, b'link', [None, 511, b'root', b'root'], 12, 1, None,
                b'\x00\xa0zerotier-one']
        for index, value in ((3, 13), (5, b'hash'), (6, b'\0\x20zerotier-one'),
                             (6, b'\0\xa0../outside')):
            member = list(base)
            member[index] = value
            with self.subTest(index=index), self.assertRaises(ValueError):
                member_record(member)


if __name__ == '__main__':
    unittest.main()
