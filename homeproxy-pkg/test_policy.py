"""Focused contracts for the F50 capability patch and package evidence."""
import copy
import hashlib
import unittest

from model import audit_package, verify_kernel
from patch_features import patch_rpc


class PolicyTests(unittest.TestCase):
    def test_unpinned_rpc_source_is_rejected(self):
        with self.assertRaises(ValueError):
            patch_rpc(b'unreviewed source')

    def test_kernel_report_binds_release_status_size_and_builtins(self):
        config = b'CONFIG_TUN=y\nCONFIG_NFT_TPROXY=y\nCONFIG_INET_TCP_DIAG=y\n'
        report = {'status': 'PASS', 'kernel': {'release': '7.2.8-f50-dae1'}, 'artifacts': [
            {'path': '/out/.config', 'sha256': hashlib.sha256(config).hexdigest(), 'size': len(config)}]}
        verify_kernel(config, report)
        for field, value in [('status', 'FAIL'), ('kernel', {'release': '6.12.94'})]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                verify_kernel(config, dict(report, **{field: value}))
        with self.assertRaises(ValueError):
            verify_kernel(config + b'\n', report)

    def test_payload_metadata_and_scripts_must_match(self):
        info = {'name': 'test', 'version': '1-r1', 'arch': 'noarch'}
        expected = {'files': {'file': {'size': 5}}, 'directories': {}, 'scripts': {}}
        candidate = dict(copy.deepcopy(expected), info=dict(info, **{'installed-size': 5}),
                         signature_blocks=1, package_fields={})
        audit_package(candidate, expected, info)
        for field in ('files', 'directories', 'scripts'):
            altered = dict(candidate, **{field: {'drift': True}})
            with self.subTest(field=field), self.assertRaises(ValueError):
                audit_package(altered, expected, info)


if __name__ == '__main__':
    unittest.main()
