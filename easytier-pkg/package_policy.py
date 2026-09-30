"""Exact EasyTier package transformation allowlist, bound to F50 TUN evidence."""
import hashlib
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'packaging'))
from apk3 import require
from package_audit import read_config, verify_config_binding

INIT_PATH = 'etc/init.d/easytier'
CORE_VERSION = '2.6.4-r1'
UI_VERSION = '2.6.4-r3'
DESCRIPTION = '; F50 adaptation: TUN builtin, paired core, reviewed disabled-start/stop and launcher-log fixes; see packaging-manifest.json'


def verify_kernel(report, content):
    require(report.get('status') == 'PASS', 'Kernel validation must pass')
    require(report.get('kernel', {}).get('release') == '7.2.8-f50-dae1', 'Unreviewed kernel')
    binding = verify_config_binding(report, content)
    require(read_config(content).get('CONFIG_TUN') == 'y', 'TUN must be built in')
    return {'release': '7.2.8-f50-dae1', 'config_binding': binding, 'CONFIG_TUN': 'y',
            'device_runtime_tested_by_packager': False}


def expected_info(info, options):
    name = info['name']
    require(name == options['name'], 'Unexpected package name')
    dependencies = list(info['depends'])
    if name in ('easytier', 'luci-app-easytier'):
        require(dependencies.count('kmod-tun') == 1, 'Expected one TUN dependency')
        dependencies.remove('kmod-tun')
    require(not any(d.startswith('kmod-') or d == 'kernel' for d in dependencies),
            'Unexpected remaining kernel dependency')
    if name == 'luci-app-easytier':
        require('easytier' not in dependencies, 'Unexpected upstream core dependency')
        dependencies.append('easytier=' + CORE_VERSION)
    elif name == 'luci-i18n-easytier-zh-cn':
        require(dependencies.count('luci-app-easytier') == 1, 'Unexpected translation dependency')
        dependencies = ['luci-app-easytier=' + UI_VERSION if d == 'luci-app-easytier' else d
                        for d in dependencies]
    else:
        require(name == 'easytier', 'Unreviewed package')
    return dict(info, version=options['version'], depends=sorted(dependencies),
                description=info['description'] + DESCRIPTION,
                **{'installed-size': info['installed-size'] + options.get('init_size_delta', 0)})


def expected_files(source, patched_init):
    files = dict(source['files'])
    if patched_init is not None:
        require(INIT_PATH in files, 'Missing original init')
        files[INIT_PATH] = dict(files[INIT_PATH], size=len(patched_init),
                                sha256=hashlib.sha256(patched_init).hexdigest())
    return files


def audit_package(source, candidate, options):
    patched = options.get('patched_init')
    require(candidate['files'] == expected_files(source, patched), 'Unreviewed payload change')
    for field in ('directories', 'scripts', 'package_fields'):
        require(candidate[field] == source[field], f'Unreviewed {field} change')
    require(source['signature_blocks'] == 1 and candidate['signature_blocks'] == 1,
            'Expected one upstream and one new output signature')
    expected = expected_info(source['info'], options)
    actual = candidate['info']
    require({k: v for k, v in expected.items() if k != 'hashes'} ==
            {k: v for k, v in actual.items() if k != 'hashes'}, 'Unexpected metadata change')
    changes = {k: {'before': source['info'].get(k), 'after': actual.get(k)}
               for k in sorted(source['info'].keys() | actual.keys())
               if source['info'].get(k) != actual.get(k)}
    return {'metadata_changes': changes, 'payload_changes': [INIT_PATH] if patched else [],
            'files': candidate['files'], 'directories': candidate['directories'],
            'lifecycle_script_changes': [],
            'scripts': {name: {'size': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
                        for name, body in candidate['scripts'].items()}}
