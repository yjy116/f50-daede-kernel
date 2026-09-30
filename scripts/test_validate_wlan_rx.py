"""Parser/gate tests; these fixtures do not claim an actual module was compiled."""
import unittest
from pathlib import Path


LAYOUT = '__u8 ip_summed:2; /* 128: 3 1 */'
ASSEMBLY = '''
0000000000000000 <sc2355_fill_skb_csum>:
   0: ldrb w1, [x0, #128]
   4: and w1, w1, #0xffffffe7
   8: strb w1, [x0, #128]
   c: mov w0, #0x0
  10: ret
'''


class SoftwareChecksumGateTests(unittest.TestCase):
    def verify(self, assembly=ASSEMBLY, layout=LAYOUT):
        from validate_wlan_rx import verify_software_checksum
        return verify_software_checksum(assembly, layout)

    def test_proves_two_checksum_bits_cleared_and_zero_return(self):
        report = self.verify()
        self.assertEqual(report['ip_summed_byte_offset'], 128)
        self.assertEqual(report['ip_summed_bit_offset'], 3)
        self.assertEqual(report['checksum_none_mask'], 0xe7)

    def test_rejects_old_conditional_hardware_checksum_path(self):
        with self.assertRaises(ValueError):
            self.verify(ASSEMBLY.replace('and w1, w1, #0xffffffe7', 'cbz w1, 18'))

    def test_rejects_store_to_another_field(self):
        with self.assertRaisesRegex(ValueError, 'store'):
            self.verify(ASSEMBLY.replace('strb w1, [x0, #128]', 'strb w1, [x0, #129]'))

    def test_rejects_wrong_mask_or_nonzero_return(self):
        for before, after in (('0xffffffe7', '0xffffffef'), ('mov w0, #0x0', 'mov w0, #0x1')):
            with self.subTest(after=after), self.assertRaises(ValueError):
                self.verify(ASSEMBLY.replace(before, after))

    def test_rejects_missing_function_or_layout(self):
        for assembly, layout in (('', LAYOUT), (ASSEMBLY, 'struct sk_buff { };')):
            with self.subTest(assembly=bool(assembly)), self.assertRaises(ValueError):
                self.verify(assembly, layout)

    def test_rejects_overwriting_the_pointer_or_discarding_the_byte(self):
        for register in ('w0', 'w31'):
            with self.subTest(register=register), self.assertRaises(ValueError):
                self.verify(ASSEMBLY.replace('w1', register))


class ActualLayoutTests(unittest.TestCase):
    def test_both_actual_kernel_layouts_and_helper_disassemblies(self):
        from validate_wlan_rx import verify_software_checksum
        fixtures = Path(__file__).parent / 'fixtures/wlan-rx'
        for version in ('6.18.54', '7.2.8'):
            with self.subTest(version=version):
                assembly = (fixtures / (version + '-helper.disasm')).read_text()
                layout = (fixtures / (version + '-layout.txt')).read_text()
                report = verify_software_checksum(assembly, layout)
                self.assertEqual(report['ip_summed_byte_offset'], 128)
                self.assertEqual(report['ip_summed_bit_offset'], 5)
                self.assertEqual(report['checksum_none_mask'], 0x9f)

    def test_conflicting_named_alias_offsets_are_rejected(self):
        from validate_wlan_rx import checksum_layout
        fixtures = Path(__file__).parent / 'fixtures/wlan-rx'
        for version in ('6.18.54', '7.2.8'):
            layout = (fixtures / (version + '-layout.txt')).read_text()
            changed = layout.replace('ip_summed:2;          /*   128:',
                                     'ip_summed:2;          /*   129:', 1)
            self.assertNotEqual(changed, layout)
            with self.subTest(version=version), self.assertRaises(ValueError):
                checksum_layout(changed)


if __name__ == '__main__':
    unittest.main()
