"""Package contract tests; real APK creation and ARM64 execution run in Docker."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


class ContractTests(unittest.TestCase):
    def model(self):
        path = HERE / 'model.py'
        self.assertTrue(path.exists(), 'OpenClash package contract is not implemented')
        spec = importlib.util.spec_from_file_location('openclash_model', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def candidate(self):
        model = self.model()
        info = model.package_specs()[0]['info']
        expected = {'files': {}, 'directories': {}, 'scripts': {}}
        candidate = dict(expected, info=dict(info, **{'installed-size': 0}),
                         signature_blocks=1, package_fields={})
        return model, (candidate, expected, info)

    def test_ui_version_and_core_dependency_are_exact(self):
        specs = self.model().package_specs()
        ui, core = specs
        self.assertEqual(ui['info']['version'], '0.47.167-r1')
        self.assertEqual(core['info']['version'], '1.19.31-r1')
        self.assertIn('mihomo-openclash=1.19.31-r1', ui['info']['depends'])
        self.assertFalse(any(d.startswith('kmod-') for s in specs for d in s['info'].get('depends', [])))
        self.assertEqual(core['info']['arch'], 'aarch64_generic')

    def test_dependencies_are_canonical_apk_order(self):
        info = self.model().package_specs()[0]['info']
        self.assertEqual(info['depends'], sorted(info['depends']))

    def test_kernel_report_must_pass_for_the_target_release(self):
        model = self.model()
        config = b'CONFIG_TUN=y\nCONFIG_NFT_TPROXY=y\n'
        report = {'status': 'PASS', 'kernel': {'release': '7.2.8-f50-dae1'},
                  'artifacts': [{'path': '/src/.config', 'sha256': hashlib.sha256(config).hexdigest()}]}
        model.verify_kernel(config, report)
        failed = dict(report, status='FAIL')
        with self.assertRaisesRegex(ValueError, 'report'):
            model.verify_kernel(config, failed)
        wrong_release = dict(report, kernel={'release': '6.12.0'})
        with self.assertRaisesRegex(ValueError, 'release'):
            model.verify_kernel(config, wrong_release)

    def test_exact_contract_accepts_only_expected_metadata(self):
        model, args = self.candidate()
        model.audit_package(*args)
        changed = copy.deepcopy(args[0])
        changed['info']['depends'].append('unexpected-package')
        with self.assertRaisesRegex(ValueError, 'metadata'):
            model.audit_package(changed, args[1], args[2])

    def test_unreviewed_files_or_script_changes_fail(self):
        model, args = self.candidate()
        for field in ('files', 'directories', 'scripts'):
            changed = copy.deepcopy(args[0])
            changed[field]['unreviewed'] = 'changed'
            with self.assertRaisesRegex(ValueError, field):
                model.audit_package(changed, args[1], args[2])

    def test_signature_and_installed_size_are_checked(self):
        model, args = self.candidate()
        changed = copy.deepcopy(args[0])
        changed['signature_blocks'] = 0
        with self.assertRaisesRegex(ValueError, 'signature'):
            model.audit_package(changed, args[1], args[2])
        changed = copy.deepcopy(args[0])
        changed['info']['installed-size'] = 100
        with self.assertRaisesRegex(ValueError, 'size'):
            model.audit_package(changed, args[1], args[2])

    def test_source_tar_rejects_links_and_path_escape(self):
        model = self.model()
        import tarfile
        for path in ('prefix/../escape', '/outside', 'prefix/file'):
            member = tarfile.TarInfo(path)
            if path == 'prefix/file':
                member.type = tarfile.SYMTYPE
                member.linkname = '/outside'
            with self.assertRaises(ValueError):
                model.validate_member(member, 'prefix/')

    def test_disabled_default_is_section_specific(self):
        model = self.model()
        valid = "config openclash 'config'\n option enable '0'\nconfig auth 'other'\n option enabled '1'\n"
        model.verify_disabled(valid)
        with self.assertRaisesRegex(ValueError, 'disabled'):
            model.verify_disabled(valid.replace("enable '0'", "enable '1'"))
        with self.assertRaisesRegex(ValueError, 'disabled'):
            model.verify_disabled(valid.replace("config openclash 'config'", "config auth 'config'"))

    def test_snapshot_rejects_symlink_without_claiming_windows_support(self):
        model = self.model()
        if __import__('os').name == 'nt':
            self.skipTest('Real symlink permission behavior is checked in Linux Docker')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'bad').symlink_to('/outside')
            with self.assertRaisesRegex(ValueError, 'symlink'):
                model.snapshot(root)


if __name__ == '__main__':
    unittest.main()
