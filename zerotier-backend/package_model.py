"""Explicit ZeroTier p2 backend overlay; preserve every unlisted upstream byte."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'packaging'))
from apk3 import require

VERSION = '1.16.0_p2-r1'
FILE_LIST = 'lib/apk/packages/zerotier.list'
DERIVED = {'hashes', 'installed-size', 'file-size'}
DESCRIPTION = '; F50 p2: reviewed per-network and fw4 controls; original core binary'


def expected_info(info):
    dependencies = list(info['depends'])
    require(dependencies.count('kmod-tun') == 1, 'Expected original TUN dependency')
    dependencies.remove('kmod-tun')
    require(not {'firewall4', 'jshn'} & set(dependencies), 'Unexpected existing control dependency')
    dependencies.extend(['firewall4', 'jshn'])
    return dict(info, version=VERSION, depends=sorted(dependencies), origin='f50/zerotier-backend',
                description=info['description'] + DESCRIPTION)


def lifecycle_scripts(source):
    scripts = dict(source['scripts'])
    registration = (HERE / 'post-install.sh').read_bytes()
    scripts['post-install'] = registration
    scripts['post-upgrade'] = registration
    return scripts


def payload_paths():
    reviewed = json.loads((HERE / 'payload.json').read_text())
    actual = sorted(path.relative_to(HERE / 'root').as_posix()
                    for path in (HERE / 'root').rglob('*') if path.is_file())
    require(actual == sorted(reviewed), 'Backend payload differs from explicit allowlist')
    require('etc/init.d/zerotier' in reviewed, 'Missing reviewed init')
    return reviewed


def record_regular(path):
    stat = path.stat()
    return {'mode': stat.st_mode & 0o7777, 'user': 'root', 'group': 'root',
            'size': stat.st_size, 'mtime': int(stat.st_mtime), 'type': 'regular',
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def overlay_file(root, name, timestamp):
    source = HERE / 'root' / name
    require(source.is_file() and not source.is_symlink(), f'Invalid overlay: {name}')
    destination = root / name
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(source.read_bytes())
    destination.chmod(0o755)
    os.utime(destination, (timestamp, timestamp))
    return record_regular(destination)


def include_directories(root, expected):
    for path in [root, *root.rglob('*')]:
        if not path.is_dir() or path.is_symlink():
            continue
        name = '' if path == root else path.relative_to(root).as_posix()
        if name not in expected:
            path.chmod(0o755)
            expected[name] = {'mode': 0o755, 'user': 'root', 'group': 'root'}


def stage_files(root, source):
    expected = {key: copy.deepcopy(source[key]) for key in ('files', 'directories')}
    timestamp = source['files']['etc/init.d/zerotier']['mtime']
    reviewed = payload_paths()
    for name in reviewed:
        require(name == 'etc/init.d/zerotier' or name not in source['files'],
                f'Unreviewed upstream replacement: {name}')
        expected['files'][name] = overlay_file(root, name, timestamp)
    listing = root / FILE_LIST
    original = listing.read_text().splitlines()
    additions = ['/' + name for name in reviewed if '/' + name not in original]
    listing.write_text('\n'.join(original + sorted(additions)) + '\n', encoding='utf-8')
    os.utime(listing, (timestamp, timestamp))
    expected['files'][FILE_LIST] = record_regular(listing)
    include_directories(root, expected['directories'])
    expected['scripts'] = lifecycle_scripts(source)
    return expected


def audit_package(source, candidate, expected):
    for key in ('files', 'directories', 'scripts'):
        require(candidate[key] == expected[key], f'Unexpected {key} drift')
    require(candidate['signature_blocks'] == 1, 'Expected one package signature')
    require(candidate['package_fields'] == source['package_fields'], 'Package extensions changed')
    info = {key: value for key, value in candidate['info'].items() if key not in DERIVED}
    required = {key: value for key, value in expected_info(source['info']).items()
                if key not in DERIVED}
    differences = {key: {'expected': required.get(key), 'actual': info.get(key)}
                   for key in sorted(info.keys() | required.keys())
                   if info.get(key) != required.get(key)}
    require(not differences, f'Unexpected backend metadata change: {json.dumps(differences)}')
    installed_size = sum(f['size'] for f in expected['files'].values() if f['type'] == 'regular')
    require(candidate['info']['installed-size'] == installed_size,
            'Backend installed size mismatch')
    binary = 'usr/bin/zerotier-one'
    require(candidate['files'][binary] == source['files'][binary], 'Core binary changed')
