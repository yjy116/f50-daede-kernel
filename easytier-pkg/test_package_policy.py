"""Reject changes beyond the paired package metadata and exact patched init."""
import copy
import hashlib
import unittest

from package_policy import INIT_PATH, audit_package, expected_files, expected_info


class PackagePolicyTests(unittest.TestCase):
    def setUp(self):
        self.source = {
            'info': {'name': 'luci-app-easytier', 'version': '2.6.4-r1', 'description': 'UI',
                     'installed-size': 10, 'depends': ['kmod-tun', 'libc', 'luci-compat']},
            'files': {INIT_PATH: {'size': 4, 'sha256': 'old', 'mode': 420, 'mtime': 123},
                      'etc/config/easytier': {'sha256': 'unchanged', 'mode': 420}},
            'directories': {'': {'mode': 493}}, 'scripts': {'post-install': b'original'},
            'package_fields': {}, 'signature_blocks': 1,
        }
        self.options = {'name': 'luci-app-easytier', 'version': '2.6.4-r3',
                        'patched_init': b'patched', 'init_size_delta': 3}
        self.candidate = dict(copy.deepcopy(self.source),
                              info=expected_info(self.source['info'], self.options),
                              files=expected_files(self.source, b'patched'))

    def test_reviewed_init_and_exact_core_dependency(self):
        audit_package(self.source, self.candidate, self.options)
        self.assertEqual(self.candidate['files'][INIT_PATH]['sha256'],
                         hashlib.sha256(b'patched').hexdigest())
        self.assertEqual(self.candidate['info']['depends'],
                         ['easytier=2.6.4-r1', 'libc', 'luci-compat'])

    def test_unrelated_file_script_or_permission_changes_fail(self):
        changes = [lambda p: p['files']['etc/config/easytier'].update(sha256='changed'),
                   lambda p: p['files'][INIT_PATH].update(mode=493),
                   lambda p: p['files'][INIT_PATH].update(mtime=456),
                   lambda p: p['scripts'].update({'post-install': b'changed'}),
                   lambda p: p.update(signature_blocks=2),
                   lambda p: p['info'].update(provides=['kmod-tun'])]
        for change in changes:
            candidate = copy.deepcopy(self.candidate)
            change(candidate)
            with self.subTest(change=change), self.assertRaises(ValueError):
                audit_package(self.source, candidate, self.options)

    def test_core_and_translation_dependencies(self):
        core = dict(self.source['info'], name='easytier', depends=['kmod-tun', 'libc'])
        self.assertEqual(expected_info(core, {'name': 'easytier', 'version': '2.6.4-r1'})['depends'], ['libc'])
        zh = dict(core, name='luci-i18n-easytier-zh-cn', depends=['libc', 'luci-app-easytier'])
        options = {'name': zh['name'], 'version': '26.136.03667~39d7eda-r2'}
        self.assertEqual(expected_info(zh, options)['depends'], ['libc', 'luci-app-easytier=2.6.4-r3'])


if __name__ == '__main__':
    unittest.main()
