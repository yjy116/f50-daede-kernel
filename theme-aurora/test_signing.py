"""Reject any change beyond the single newly added APK3 signature block."""
import copy
import struct
import unittest
import zlib

from audit import audit_models, unsigned_blocks


def apk_bytes(chunks):
    raw = bytearray(b'ADB.pckg')
    for kind, body in chunks:
        size = len(body) + 4
        raw.extend(struct.pack('<I', kind << 30 | size) + body)
        raw.extend(b'\0' * (-size % 8))
    return b'ADBd' + zlib.compress(bytes(raw), wbits=-15)


class SigningAuditTests(unittest.TestCase):
    def setUp(self):
        self.source = {
            'info': {'name': 'luci-theme-aurora', 'depends': ['libc', 'luci-base']},
            'files': {'asset': {'sha256': 'a' * 64, 'size': 2, 'mode': 420}},
            'directories': {'': {'mode': 493, 'user': 'root', 'group': 'root'}},
            'scripts': {'post-install': b'#!/bin/sh\nexit 0\n'},
            'package_fields': {}, 'selected_contents': {}, 'signature_blocks': 0,
            'apk_size': 100, 'apk_sha256': 'source',
        }
        self.signed = dict(copy.deepcopy(self.source), signature_blocks=1,
                           apk_size=200, apk_sha256='signed')

    def test_only_signature_and_outer_container_may_change(self):
        audit_models(self.source, self.signed)

    def test_every_preserved_field_rejects_mutation(self):
        for field in set(self.source) - {'apk_size', 'apk_sha256', 'signature_blocks'}:
            candidate = copy.deepcopy(self.signed)
            candidate[field] = {'modified': True}
            with self.subTest(field=field), self.assertRaises(ValueError):
                audit_models(self.source, candidate)

    def test_signature_count_and_unrecognized_fields_fail(self):
        for count in (0, 2):
            with self.subTest(count=count), self.assertRaises(ValueError):
                audit_models(self.source, dict(self.signed, signature_blocks=count))
        with self.assertRaises(ValueError):
            audit_models(dict(self.source, signature_blocks=1), self.signed)
        with self.assertRaises(ValueError):
            audit_models(self.source, dict(self.signed, unexpected='field'))

    def test_raw_metadata_data_and_padding_are_retained(self):
        source = apk_bytes([(0, b'metadata'), (2, b'payload')])
        signed = apk_bytes([(0, b'metadata'), (1, b'signature'), (2, b'payload')])
        self.assertEqual(unsigned_blocks(source), unsigned_blocks(signed))
        changed = apk_bytes([(0, b'Metadata'), (1, b'signature'), (2, b'payload')])
        self.assertNotEqual(unsigned_blocks(source), unsigned_blocks(changed))

    def test_truncated_or_trailing_compression_fails(self):
        packed = apk_bytes([(0, b'metadata')])
        for invalid in (packed[:-1], packed + b'trailing', b'ADBc' + packed[4:]):
            with self.subTest(invalid=invalid[:4]), self.assertRaises(ValueError):
                unsigned_blocks(invalid)


if __name__ == '__main__':
    unittest.main()
