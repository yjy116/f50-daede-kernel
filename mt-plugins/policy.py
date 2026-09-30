"""F50-only metadata policy: preserve every upstream file and lifecycle script."""
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'packaging'))
from apk3 import require
from package_audit import read_config, verify_config_binding

REMOVED = {'nlbwmon': 'kmod-nf-conntrack-netlink', 'tailscale': 'kmod-tun',
           'libnetfilter-conntrack3': 'kmod-nf-conntrack-netlink'}
BUILTINS = {'kmod-tun': ['CONFIG_TUN'],
            'kmod-nf-conntrack-netlink': ['CONFIG_NF_CT_NETLINK', 'CONFIG_NF_CONNTRACK',
                                        'CONFIG_NF_CONNTRACK_EVENTS']}
SUFFIX = '; F50-only metadata adaptation: reviewed kernel dependency is built in; upstream payload and scripts unchanged; see packaging-manifest.json'


def expected_info(info, policy):
    name = info['name']
    require(name == policy['name'] and name in REMOVED, 'Unreviewed package')
    dependency = REMOVED[name]
    dependencies = info['depends']
    require(dependencies.count(dependency) == 1, 'Expected exactly one reviewed kmod dependency')
    require([d for d in dependencies if d.startswith('kmod-') or d == 'kernel'] == [dependency],
            'Unexpected kernel dependency')
    return dict(info, version=policy['version'], description=info['description'] + SUFFIX,
                depends=[d for d in dependencies if d != dependency])


def audit_package(source, candidate, policy):
    for field in ('files', 'directories', 'scripts', 'package_fields'):
        require(source[field] == candidate[field], f'Upstream {field} changed')
    require(source['signature_blocks'] == 0, 'Pinned source must be unsigned')
    require(candidate['signature_blocks'] == 1, 'Exactly one output signature required')
    expected = expected_info(source['info'], policy)
    actual = candidate['info']
    require({k: v for k, v in expected.items() if k != 'hashes'} ==
            {k: v for k, v in actual.items() if k != 'hashes'}, 'Unreviewed metadata change')
    keys = source['info'].keys() | actual.keys()
    changes = {key: {'before': source['info'].get(key), 'after': actual.get(key)}
               for key in sorted(keys) if source['info'].get(key) != actual.get(key)}
    return {'metadata_changes': changes, 'payload_changes': [], 'lifecycle_script_changes': [],
            'files': candidate['files'], 'directories': candidate['directories'],
            'scripts': {name: {'size': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
                        for name, body in candidate['scripts'].items()}}


def verify_kernel(report, content):
    require(report.get('status') == 'PASS', 'Kernel validation must pass')
    release = report.get('kernel', {}).get('release')
    require(release == '7.2.8-f50-dae1', 'Only the reviewed F50 kernel release is supported')
    binding = verify_config_binding(report, content)
    config = read_config(content)
    values = {symbol: config.get(symbol) for symbols in BUILTINS.values() for symbol in symbols}
    require(all(value == 'y' for value in values.values()),
            'Required builtins missing: ' + json.dumps(values))
    return {'release': release, 'config_binding': binding, 'builtin_mapping': BUILTINS,
            'verified_values': values, 'device_runtime_tested_by_packager': False}
