"""Negative tests for packaging invariants; never execute target binaries/scripts."""
import copy
import hashlib
import unittest

from package_audit import (ADDITIONAL_REQUIRED, BUILTIN_MAPPING, audit_repack,
                           expected_info, verify_kernel_evidence)


def source_package(name='daed'):
    deps = ['ca-bundle', 'kmod-sched-bpf', 'kmod-sched-core', 'kmod-veth',
            'libc', 'v2ray-geoip', 'v2ray-geosite']
    if name != 'daed':
        deps = ['daed', 'libc', 'luci-base']
    return {
        'info': {'name': name, 'version': '1-r1', 'description': 'Upstream',
                 'depends': deps, 'hashes': 'old', 'installed-size': 3},
        'directories': {'': {'mode': 493, 'user': 'root', 'group': 'root'}},
        'files': {'usr/bin/daed': {'size': 3, 'sha256': 'unchanged', 'mode': 493}},
        'scripts': {'post-install': b'#!/bin/sh\nexit 0\n'},
        'package_fields': {}, 'signature_blocks': 0,
    }


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.source = source_package()
        self.policy = {'version': '1_p1-r1', 'description_suffix': '; F50 built-ins'}
        self.repacked = copy.deepcopy(self.source)
        self.repacked['info'] = expected_info(self.source['info'], self.policy)
        self.repacked['info']['hashes'] = 'new'
        self.repacked['signature_blocks'] = 1

    def test_only_declared_metadata_changes_pass(self):
        result = audit_repack(self.source, self.repacked, self.policy)
        self.assertEqual(result['payload_changes'], [])
        self.assertEqual(set(result['metadata_changes']),
                         {'version', 'description', 'depends', 'hashes'})

    def test_payload_mode_script_extra_dependency_and_metadata_fail(self):
        mutations = [
            lambda p: p['files']['usr/bin/daed'].update(sha256='different'),
            lambda p: p['files']['usr/bin/daed'].update(mode=420),
            lambda p: p['directories'][''].update(mode=511),
            lambda p: p['scripts'].update({'post-install': b'exit 0'}),
            lambda p: p['info']['depends'].append('kmod-veth'),
            lambda p: p['info'].update(license='changed'),
            lambda p: p.update(signature_blocks=0),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                candidate = copy.deepcopy(self.repacked)
                mutate(candidate)
                with self.assertRaises(ValueError):
                    audit_repack(self.source, candidate, self.policy)

    def test_missing_removed_dependency_is_not_silently_accepted(self):
        self.source['info']['depends'].remove('kmod-veth')
        with self.assertRaises(ValueError):
            expected_info(self.source['info'], self.policy)

    def test_luci_exact_dependency(self):
        source = source_package('luci-app-daede')
        policy = dict(self.policy, daed_version='2026.09.24_p1-r2')
        actual = expected_info(source['info'], policy)
        self.assertEqual(actual['depends'],
                         ['daed=2026.09.24_p1-r2', 'libc', 'luci-base'])

    def test_symlink_target_change_is_rejected(self):
        link = {'type': 'symlink', 'mode': 511, 'target': 'zerotier-one'}
        self.source['files']['usr/bin/zerotier-cli'] = dict(link)
        self.repacked['files']['usr/bin/zerotier-cli'] = dict(link, target='wrong')
        with self.assertRaises(ValueError):
            audit_repack(self.source, self.repacked, self.policy)

    def test_failed_build_evidence_is_rejected(self):
        with self.assertRaises(ValueError):
            verify_kernel_evidence({'status': 'FAIL'}, b'')

    def test_old_kernel_and_module_instead_of_builtin_are_rejected(self):
        evidence = {'status': 'PASS', 'kernel': {'release': '6.12.94'},
                    'config': {'requested_values': {}}}
        with self.assertRaises(ValueError):
            verify_kernel_evidence(evidence, b'')
        evidence['kernel']['release'] = '7.2.8-f50-dae1'
        evidence['config']['requested_values'] = {'CONFIG_VETH': 'm'}
        with self.assertRaises(ValueError):
            verify_kernel_evidence(evidence, b'')

    def test_zerotier_only_removes_tun(self):
        info = {'name': 'zerotier', 'version': '1.16.0-r1', 'description': 'ZeroTier',
                'depends': ['ip', 'kmod-tun', 'libc', 'libstdcpp6'], 'provides': ['zerotier-any']}
        actual = expected_info(info, dict(self.policy, version='1.16.0_p1-r1'))
        self.assertEqual(actual['depends'], ['ip', 'libc', 'libstdcpp6'])
        self.assertEqual(actual['provides'], info['provides'])
        with self.assertRaises(ValueError):
            expected_info(dict(info, depends=['ip', 'libc']), self.policy)

    def test_actual_config_hash_and_builtin_tun_are_required(self):
        names = set(ADDITIONAL_REQUIRED).union(*BUILTIN_MAPPING.values())
        config = ''.join(f'{name}=y\n' for name in sorted(names)).encode()
        evidence = {'status': 'PASS', 'kernel': {'release': '7.2.8-f50-dae1'},
                    'artifacts': [{'path': '/src/out-7.2.8/.config', 'size': len(config),
                                   'sha256': hashlib.sha256(config).hexdigest()}]}
        self.assertEqual(verify_kernel_evidence(evidence, config)['verified_values']['CONFIG_TUN'], 'y')
        with self.assertRaises(ValueError):
            verify_kernel_evidence(evidence, config + b'\n')
        disabled = config.replace(b'CONFIG_TUN=y', b'CONFIG_TUN=m')
        evidence['artifacts'][0].update(size=len(disabled), sha256=hashlib.sha256(disabled).hexdigest())
        with self.assertRaises(ValueError):
            verify_kernel_evidence(evidence, disabled)


if __name__ == '__main__':
    unittest.main()
