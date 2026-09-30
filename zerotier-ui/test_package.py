"""Package audit must reject changed payloads, scripts, metadata and signatures."""
import copy
import unittest

from package_model import audit_package, package_info


class PackageAuditTests(unittest.TestCase):
    def setUp(self):
        self.info = package_info()
        self.expected = {
            'files': {'www/test.js': {'size': 4, 'mode': 420, 'sha256': 'a' * 64}},
            'directories': {'': {'mode': 493, 'user': 'root', 'group': 'root'}},
            'scripts': {'post-install': b'#!/bin/sh\nexit 0\n'},
        }
        self.candidate = dict(copy.deepcopy(self.expected), package_fields={}, signature_blocks=1,
                              info=dict(self.info, hashes='identity', **{'installed-size': 4}))

    def test_exact_package_passes(self):
        audit_package(self.candidate, self.expected)

    def test_changed_payload_script_dependency_mode_or_unsigned_package_fails(self):
        mutations = [
            lambda p: p['files']['www/test.js'].update(sha256='b' * 64),
            lambda p: p['directories'][''].update(mode=511),
            lambda p: p['scripts'].update({'post-install': b'changed'}),
            lambda p: p['info'].update(depends=['zerotier']),
            lambda p: p['info'].update(provides=['kernel']),
            lambda p: p['info'].update({'installed-size': 5}),
            lambda p: p.update(signature_blocks=0),
        ]
        for mutate in mutations:
            candidate = copy.deepcopy(self.candidate)
            mutate(candidate)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                audit_package(candidate, self.expected)


if __name__ == '__main__':
    unittest.main()
