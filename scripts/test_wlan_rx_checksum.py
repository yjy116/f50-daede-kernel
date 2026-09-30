"""Exercise the fixed upstream source and real Git patch application."""
import os
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent


class BuildIntegrationTests(unittest.TestCase):
    def test_mainline_modules_are_patched_before_the_vendor_build(self):
        build = (HERE / 'build.sh').read_text(encoding='utf-8')
        self.assertIn('wlan_rx_checksum.py apply', build)
        self.assertLess(build.index('wlan_rx_checksum.py apply'),
                        build.index('bash /work/build-modules.sh'))
        self.assertIn('--module-dir /work/modules/sprd_wlan_combo', build)

    def test_final_module_has_a_software_checksum_validation_gate(self):
        build = (HERE / 'build.sh').read_text(encoding='utf-8')
        self.assertIn('validate_wlan_rx.py', build)
        self.assertLess(build.index('strip --strip-debug'),
                        build.index('validate_wlan_rx.py'))


class SourcePatchTests(unittest.TestCase):
    def setUp(self):
        import wlan_rx_checksum as patcher
        self.patcher = patcher
        self.upstream = Path(os.environ['F50_TEST_UPSTREAM']).resolve()
        self.temporary = tempfile.TemporaryDirectory(prefix='f50-wlan-rx-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.module = self.root / 'modules/sprd_wlan_combo'
        self.target = self.module / patcher.SOURCE_RELATIVE
        self.target.parent.mkdir(parents=True)
        source = self.upstream / 'upstream/modules/sprd_wlan_combo' / patcher.SOURCE_RELATIVE
        shutil.copyfile(source, self.target)
        self.options = SimpleNamespace(source_root=self.upstream, module_dir=self.module,
                                       output=self.root / 'evidence/wlan-rx-source.json')

    def test_real_upstream_patch_changes_the_compiled_source(self):
        report = self.patcher.apply_source_patch(self.options)
        self.assertEqual(report['before_sha256'], self.patcher.BEFORE_SHA256)
        self.assertEqual(report['after_sha256'], self.patcher.AFTER_SHA256)
        self.assertEqual(self.patcher.digest(self.target), self.patcher.AFTER_SHA256)
        self.assertEqual(report['git_apply_check_exit'], 0)
        self.assertEqual(report['git_apply_exit'], 0)

    def test_changed_source_is_rejected_without_modification(self):
        self.target.write_bytes(self.target.read_bytes() + b'\n/* source drift */\n')
        original = self.target.read_bytes()
        with self.assertRaisesRegex(ValueError, 'Unpatched WLAN source hash mismatch'):
            self.patcher.apply_source_patch(self.options)
        self.assertEqual(self.target.read_bytes(), original)

    def test_reapplying_is_an_error_not_a_silent_skip(self):
        self.patcher.apply_source_patch(self.options)
        with self.assertRaisesRegex(ValueError, 'Unpatched WLAN source hash mismatch'):
            self.patcher.apply_source_patch(self.options)

    def test_ambient_git_line_endings_do_not_change_patch_bytes(self):
        original = self.target.read_bytes()
        for autocrlf in ('true', 'false'):
            environment = {'GIT_CONFIG_COUNT': '2', 'GIT_CONFIG_KEY_0': 'core.autocrlf',
                           'GIT_CONFIG_VALUE_0': autocrlf, 'GIT_CONFIG_KEY_1': 'core.eol',
                           'GIT_CONFIG_VALUE_1': 'crlf'}
            with self.subTest(autocrlf=autocrlf), patch.dict(os.environ, environment):
                self.target.write_bytes(original)
                self.patcher.apply_source_patch(self.options)
                self.assertEqual(self.target.read_bytes().count(b'\r'), 0)

    def test_changed_upstream_patch_is_rejected_without_modification(self):
        fake_root = self.root / 'changed-upstream'
        patch = fake_root / self.patcher.PATCH_RELATIVE
        patch.parent.mkdir(parents=True)
        patch.write_bytes((self.upstream / self.patcher.PATCH_RELATIVE).read_bytes() + b'\n')
        self.options.source_root = fake_root
        original = self.target.read_bytes()
        with self.assertRaisesRegex(ValueError, 'Upstream WLAN patch hash mismatch'):
            self.patcher.apply_source_patch(self.options)
        self.assertEqual(self.target.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
