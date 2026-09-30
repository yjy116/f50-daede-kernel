"""Only reviewed backend files and lifecycle scripts may differ from upstream."""
import copy
import unittest

from package_model import audit_package, expected_info


class BackendPackageTests(unittest.TestCase):
    def setUp(self):
        self.source = {
            'info': {'name': 'zerotier', 'version': '1.16.0-r1',
                     'depends': ['libc', 'kmod-tun'], 'description': 'ZeroTier'},
            'files': {'usr/bin/zerotier-one': {'size': 10, 'type': 'regular', 'sha256': 'a' * 64}},
            'scripts': {'pre-deinstall': b'official'}, 'package_fields': {},
        }
        self.expected = {
            'files': dict(self.source['files'], **{'etc/init.d/zerotier': {
                'size': 20, 'type': 'regular', 'sha256': 'b' * 64}}),
            'directories': {'': {'mode': 493, 'user': 'root', 'group': 'root'}},
            'scripts': {'pre-deinstall': b'official', 'post-upgrade': b'registration'},
        }
        self.candidate = dict(copy.deepcopy(self.expected), package_fields={},
                              signature_blocks=1,
                              info=dict(expected_info(self.source['info']),
                                        **{'installed-size': 30, 'hashes': 'new'}))

    def test_reviewed_backend_and_exact_binary_pass(self):
        audit_package(self.source, self.candidate, self.expected)

    def test_binary_permissions_scripts_dependencies_or_signature_drift_fails(self):
        mutations = [
            lambda p: p['files']['usr/bin/zerotier-one'].update(sha256='c' * 64),
            lambda p: p['files']['etc/init.d/zerotier'].update(mode=511),
            lambda p: p['scripts'].update({'post-upgrade': b'start daemon'}),
            lambda p: p['info'].update(depends=['libc']),
            lambda p: p['info'].update({'installed-size': 1}),
            lambda p: p.update(signature_blocks=0),
        ]
        for mutate in mutations:
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                candidate = copy.deepcopy(self.candidate)
                mutate(candidate)
                audit_package(self.source, candidate, self.expected)

    def test_kernel_dependency_removed_and_fw4_dependency_explicit(self):
        info = expected_info(self.source['info'])
        self.assertEqual(info['version'], '1.16.0_p2-r1')
        self.assertEqual(info['depends'], ['firewall4', 'jshn', 'libc'])
        self.assertIn('F50', info['description'])

    def test_apk_installed_size_excludes_symlink_target_bytes(self):
        link = {'type': 'symlink', 'size': 12, 'target': 'zerotier-one'}
        self.expected['files']['usr/bin/zerotier-cli'] = link
        self.candidate['files']['usr/bin/zerotier-cli'] = link.copy()
        audit_package(self.source, self.candidate, self.expected)


if __name__ == '__main__':
    unittest.main()
