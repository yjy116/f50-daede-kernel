"""Exact metadata and payload contracts for three small LuCI apps and vlmcsd."""
import hashlib
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'packaging'))
from apk3 import require

CORE_VERSION = '2020.03.30_p1-r8'
UI_VERSION = '26.261.08411_p1-r1'
DERIVED = {'hashes', 'installed-size', 'file-size'}
APPS = {
    'autoreboot': {'version': UI_VERSION, 'license': 'Apache-2.0', 'depends': ['luci-base']},
    'vlmcsd': {'version': UI_VERSION, 'license': 'Apache-2.0',
               'depends': ['luci-base', 'vlmcsd=' + CORE_VERSION]},
    'iperf3': {'version': '0.1_p1-r1', 'license': 'GPL-2.0',
              'depends': ['luci-base', 'rpcd-mod-file', 'iperf3=3.20-r1']},
}


def information(name, settings):
    return {'name': name, 'version': settings['version'], 'arch': settings.get('arch', 'noarch'),
            'description': settings.get('description', 'F50 reviewed MT3600BE LuCI companion: ' + name),
            'license': settings['license'], 'origin': 'f50/mt-luci',
            'url': 'https://github.com/yjy116/f50-daede-kernel', 'depends': sorted(settings['depends'])}


def package_specs():
    result = []
    for short, settings in APPS.items():
        name = 'luci-app-' + short
        result.append({'kind': 'ui', 'short': short, 'info': information(name, settings)})
        language = dict(settings, depends=[name + '=' + settings['version']])
        result.append({'kind': 'i18n', 'short': short,
                       'info': information('luci-i18n-' + short + '-zh-cn', language)})
    result.append({'kind': 'core', 'short': 'vlmcsd', 'info': information('vlmcsd', {
        'version': CORE_VERSION, 'arch': 'aarch64_generic', 'license': 'MIT',
        'depends': ['libpthread'],
        'description': 'vlmcsd e599080; F50 static ARM64 musl build, upstream disabled defaults'})})
    return result


def snapshot(root):
    files, directories = {}, {}
    for path in [root, *sorted(root.rglob('*'))]:
        require(not path.is_symlink(), f'Unreviewed symlink: {path}')
        name = '' if path == root else path.relative_to(root).as_posix()
        stat = path.stat()
        common = {'mode': stat.st_mode & 0o7777, 'user': 'root', 'group': 'root'}
        if path.is_dir():
            directories[name] = common
            continue
        files[name] = dict(common, size=stat.st_size, mtime=int(stat.st_mtime), type='regular',
                           sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    return {'files': files, 'directories': directories}


def audit_package(candidate, expected, info):
    for field in ('files', 'directories', 'scripts'):
        require(candidate[field] == expected[field], f'Unexpected {field} drift')
    require(candidate['signature_blocks'] == 1, 'Expected exactly one signature')
    require(candidate['package_fields'] == {}, 'Unexpected package extensions')
    actual = {key: value for key, value in candidate['info'].items() if key not in DERIVED}
    require(actual == info, f'Unexpected package metadata: actual={actual!r}; expected={info!r}')
    size = sum(item['size'] for item in expected['files'].values())
    require(candidate['info']['installed-size'] == size, 'Installed size mismatch')


def verify_static_elf(evidence):
    require('Machine:' in evidence['header'] and 'AArch64' in evidence['header'],
            'Core is not an AArch64 ELF')
    require('INTERP' not in evidence['program'], 'Core requires a dynamic interpreter')
    require('NEEDED' not in evidence['dynamic'], 'Core requires dynamic shared libraries')


def lifecycle_scripts(name):
    install = (HERE / 'post-install.sh').read_text().replace('@PACKAGE@', name).encode()
    upgrade = install.replace(b'#!/bin/sh\n', b'#!/bin/sh\nexport PKG_UPGRADE=1\n', 1)
    return {'post-install': install, 'post-upgrade': upgrade}
