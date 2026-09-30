"""Packaging contracts: exact dependency, scripts, config and static ELF checks."""
import copy
import importlib.util
from pathlib import Path
import unittest
import tempfile

HERE = Path(__file__).resolve().parent


class PackageContractTests(unittest.TestCase):
    def load_model(self):
        path = HERE / 'mt_model.py'
        self.assertTrue(path.is_file(), 'A model must audit produced packages before publication')
        spec = importlib.util.spec_from_file_location('mt_model', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_mutated_dependency_or_script_is_rejected(self):
        model = self.load_model()
        info = model.package_specs()[0]['info']
        expected = {'files': {'etc/test': {'size': 3}}, 'directories': {},
                    'scripts': {'post-install': b'original'}}
        good = dict(copy.deepcopy(expected), info=dict(info, **{'installed-size': 3}),
                    package_fields={}, signature_blocks=1)
        model.audit_package(good, expected, info)
        for field, change in [('depends', ['kernel']), ('installed-size', 4)]:
            changed = copy.deepcopy(good)
            changed['info'][field] = change
            with self.assertRaises(ValueError):
                model.audit_package(changed, expected, info)
        changed = copy.deepcopy(good)
        changed['scripts']['post-install'] = b'/etc/init.d/network restart'
        with self.assertRaises(ValueError):
            model.audit_package(changed, expected, info)

    def test_static_elf_evidence_rejects_host_or_dynamic_output(self):
        model = self.load_model()
        model.verify_static_elf({'header': 'Machine: AArch64', 'program': 'LOAD',
                                 'dynamic': 'There is no dynamic section in this file.'})
        for change in [{'header': 'Machine: X86-64'}, {'program': 'INTERP'},
                       {'dynamic': 'NEEDED libc.so.6'}]:
            evidence = dict(header='Machine: AArch64', program='LOAD', dynamic='')
            evidence.update(change)
            with self.assertRaises(ValueError):
                model.verify_static_elf(evidence)

    def test_application_and_language_packages_have_bound_dependencies(self):
        model = self.load_model()
        specs = {item['info']['name']: item for item in model.package_specs()}
        self.assertEqual(len(specs), 7)
        for app in ('autoreboot', 'vlmcsd', 'iperf3'):
            ui = specs['luci-app-' + app]['info']
            language = specs['luci-i18n-' + app + '-zh-cn']['info']
            self.assertEqual(language['depends'], [ui['name'] + '=' + ui['version']])
        self.assertIn('iperf3=3.20-r1', specs['luci-app-iperf3']['info']['depends'])
        self.assertIn('vlmcsd=' + specs['vlmcsd']['info']['version'],
                      specs['luci-app-vlmcsd']['info']['depends'])

    def test_source_lock_and_staged_disabled_configs(self):
        self.load_model()
        from build import verify_sources
        from stage import stage_ui, register_files
        model = self.load_model()
        self.assertGreater(len(verify_sources()['files']), 100)
        spec = next(item for item in model.package_specs()
                    if item['info']['name'] == 'luci-app-autoreboot')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stage_ui(spec, root)
            config = root / 'etc/config/autoreboot'
            original = HERE / 'vendor/luci-app-autoreboot/root/etc/config/autoreboot'
            self.assertEqual(config.read_bytes(), original.read_bytes())
            self.assertIn("option enabled '0'", config.read_text())
            register_files(spec, root)
            metadata = root / 'lib/apk/packages/luci-app-autoreboot.conffiles'
            self.assertEqual(metadata.read_text(), '/etc/config/autoreboot\n')
        core_config = (HERE / 'vendor/vlmcsd/files/vlmcsd.conf').read_text()
        for option in ('enabled', 'auto_activate', 'internet_access'):
            self.assertIn(f"option {option} '0'", core_config)

    def test_lifecycle_has_standard_registration_and_explicit_package_identity(self):
        model = self.load_model()
        scripts = model.lifecycle_scripts('luci-app-autoreboot')
        self.assertEqual(set(scripts), {'post-install', 'post-upgrade'})
        for script in scripts.values():
            self.assertIn(b"export pkgname='luci-app-autoreboot'", script)
            self.assertIn(b'default_postinst || exit $?', script)
            self.assertNotIn(b'@PACKAGE@', script)
        self.assertIn(b'export PKG_UPGRADE=1', scripts['post-upgrade'])


if __name__ == '__main__':
    unittest.main()
