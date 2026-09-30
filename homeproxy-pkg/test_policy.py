"""Focused contracts for the F50 capability patch and package evidence."""
import copy
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from model import audit_package, verify_kernel
from patch_features import patch_rpc


class PolicyTests(unittest.TestCase):
    @unittest.skipIf(os.name == 'nt', 'Linux cloud runs the real ucode compiler')
    def test_fixture_modules_compile_with_real_ucode(self):
        compiler = shutil.which('ucode')
        self.assertIsNotNone(compiler, 'Native builder must provide ucode')
        root = Path(__file__).parent / 'test-fixtures'
        with tempfile.TemporaryDirectory() as directory:
            harness = Path(directory) / 'imports.uc'
            harness.write_text("import { cursor } from 'uci';\nimport { connect } from 'ubus';\n"
                               "import { urldecode_params } from 'luci.http';\n")
            result = subprocess.run([compiler, '-L', str(root / '*.uc'), '-c',
                                     '-o', str(Path(directory) / 'test.bc'), str(harness)],
                                    capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

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
