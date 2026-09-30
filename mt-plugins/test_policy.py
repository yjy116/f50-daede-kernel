"""Mutation tests for the explicitly reviewed metadata adaptations."""
import copy
import hashlib
import unittest

from policy import audit_package, expected_info, verify_kernel


class MetadataTests(unittest.TestCase):
    def setUp(self):
        self.policy = {'name': 'tailscale', 'version': '1.98.3_p1-r1'}
        self.source = {
            'info': {'name': 'tailscale', 'version': '1.98.3-r1', 'description': 'VPN',
                     'depends': ['ca-bundle', 'kmod-tun', 'libc'], 'hashes': 'old'},
            'files': {'bin': {'mode': 493, 'sha256': 'a' * 64}},
            'directories': {'': {'mode': 493}}, 'scripts': {'post-install': b'original'},
            'package_fields': {}, 'signature_blocks': 0,
        }
        self.candidate = dict(copy.deepcopy(self.source), signature_blocks=1,
                              info=expected_info(self.source['info'], self.policy))
        self.candidate['info']['hashes'] = 'new'

    def test_only_reviewed_dependency_removed(self):
        self.assertEqual(self.candidate['info']['depends'], ['ca-bundle', 'libc'])
        audit_package(self.source, self.candidate, self.policy)

    def test_conntrack_library_preserves_all_userspace_dependencies(self):
        policy = {'name': 'libnetfilter-conntrack3', 'version': '1.1.0_p1-r1'}
        info = {'name': policy['name'], 'version': '1.1.0-r1', 'description': 'Library',
                'depends': ['kmod-nf-conntrack-netlink', 'libc', 'libmnl0', 'libnfnetlink0']}
        self.assertEqual(expected_info(info, policy)['depends'],
                         ['libc', 'libmnl0', 'libnfnetlink0'])

    def test_changed_payload_scripts_or_extra_metadata_fails(self):
        for field in ('files', 'directories', 'scripts', 'package_fields'):
            candidate = copy.deepcopy(self.candidate)
            candidate[field] = {'changed': True}
            with self.subTest(field=field), self.assertRaises(ValueError):
                audit_package(self.source, candidate, self.policy)
        for key, value in [('provides', ['kmod-tun']), ('depends', ['libc']), ('installed-size', 123)]:
            candidate = copy.deepcopy(self.candidate)
            candidate['info'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                audit_package(self.source, candidate, self.policy)

    def test_unsigned_output_and_unreviewed_dependency_schema_fail(self):
        with self.assertRaises(ValueError):
            audit_package(self.source, dict(self.candidate, signature_blocks=0), self.policy)
        for deps in (['libc'], ['kmod-tun', 'kmod-tun'], ['kmod-tun', 'kmod-unreviewed']):
            with self.subTest(deps=deps), self.assertRaises(ValueError):
                expected_info(dict(self.source['info'], depends=deps), self.policy)


class KernelTests(unittest.TestCase):
    def report(self, content):
        return {'status': 'PASS', 'kernel': {'release': '7.2.8-f50-dae1'}, 'artifacts': [
            {'path': '/src/.config', 'size': len(content), 'sha256': hashlib.sha256(content).hexdigest()}]}

    def test_config_sha_and_every_builtin_are_required(self):
        content = b'CONFIG_TUN=y\nCONFIG_NF_CT_NETLINK=y\nCONFIG_NF_CONNTRACK=y\nCONFIG_NF_CONNTRACK_EVENTS=y\n'
        verify_kernel(self.report(content), content)
        with self.assertRaises(ValueError):
            verify_kernel(self.report(content), content + b'\n')
        disabled = content.replace(b'CONFIG_NF_CT_NETLINK=y', b'CONFIG_NF_CT_NETLINK=m')
        with self.assertRaises(ValueError):
            verify_kernel(self.report(disabled), disabled)
        report = self.report(content)
        report['kernel']['release'] = '6.12.94'
        with self.assertRaises(ValueError):
            verify_kernel(report, content)


if __name__ == '__main__':
    unittest.main()
