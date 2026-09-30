"""Malformed and anonymous-member BTF fixtures; real layouts are tested separately."""
import struct
import unittest

from wlan_rx_btf import checksum_field

HEADER = struct.Struct('<HBBIIIII')
TYPE = struct.Struct('<III')
STRINGS = b'\0__u8\0ip_summed\0headers\0sk_buff\0'
NAMES = {name: STRINGS.index(name.encode()) for name in ('__u8', 'ip_summed', 'headers', 'sk_buff')}
BITFIELD_FLAG = 1 << 31
ROOT_SIZE = 160
ROOT_OFFSET = 128 * 8


def fixture(**options):
    field = TYPE.pack(NAMES['ip_summed'], 1, (options.get('width', 2) << 24) | 5)
    leaf = TYPE.pack(0, BITFIELD_FLAG | (4 << 24) | 1, 1) + field
    inner_offset = options.get('inner_offset', 0)
    anonymous = TYPE.pack(0, options.get('target', 2), inner_offset)
    alias = TYPE.pack(0 if options.get('duplicate') else NAMES['headers'], 2, 0)
    union = TYPE.pack(0, (5 << 24) | 2, 1 + inner_offset // 8) + anonymous + alias
    root = TYPE.pack(NAMES['sk_buff'], (4 << 24) | 1, options.get('root_size', ROOT_SIZE))
    root_target = 5 if options.get('modifier') else 3
    root += TYPE.pack(0, 4 if options.get('cycle') else root_target,
                      0 if options.get('cycle') else ROOT_OFFSET)
    integer = TYPE.pack(NAMES['__u8'], 1 << 24, 1) + struct.pack('<I', 8)
    types = integer + leaf + union + root
    if options.get('modifier'):
        types += TYPE.pack(0, options['modifier'] << 24, options.get('modifier_target', 3))
    header = HEADER.pack(0xeb9f, 1, 0, HEADER.size, 0, len(types), len(types), len(STRINGS))
    return header + types + STRINGS


class RawBtfTests(unittest.TestCase):
    def test_absolute_promoted_field_ignores_named_headers_alias(self):
        self.assertEqual(checksum_field(fixture()), (128, 5))

    def test_bad_width_and_duplicate_promoted_fields_fail(self):
        for options in ({'width': 1}, {'duplicate': True}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                checksum_field(fixture(**options))

    def test_nested_offsets_accumulate_without_following_named_alias(self):
        self.assertEqual(checksum_field(fixture(inner_offset=8)), (129, 5))

    def test_typedef_and_modifiers_resolve_before_container_size_checks(self):
        for modifier in (8, 9, 10, 11, 18):
            with self.subTest(modifier=modifier):
                self.assertEqual(checksum_field(fixture(modifier=modifier)), (128, 5))

    def test_modifier_cycles_and_invalid_ids_fail(self):
        for target in (0, 5, 99):
            with self.subTest(target=target), self.assertRaises(ValueError):
                checksum_field(fixture(modifier=8, modifier_target=target))

    def test_invalid_targets_cycles_and_container_overflow_fail(self):
        for options in ({'target': 99}, {'target': 0}, {'cycle': True}, {'root_size': 128}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                checksum_field(fixture(**options))

    def test_truncated_and_trailing_btf_fail(self):
        for data in (b'', fixture()[:-1], fixture() + b'\0'):
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                checksum_field(data)


if __name__ == '__main__':
    unittest.main()
