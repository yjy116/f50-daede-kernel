"""No device operations: stage and audit the F50-specific LuCI package."""
import hashlib
from pathlib import Path
import shutil
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'packaging'))
from apk3 import require

PACKAGE_NAME = 'luci-app-zerotier'
PACKAGE_VERSION = '1.1.0_p2-r1'
FILE_MODE = 0o644
DIRECTORY_MODE = 0o755
DERIVED = {'hashes', 'installed-size', 'file-size'}


def package_info():
    return {'name': PACKAGE_NAME, 'version': PACKAGE_VERSION, 'arch': 'noarch',
            'description': 'F50 Chinese ZeroTier configuration and interface UI; p2 backend controls',
            'license': 'GPL-3.0-only', 'origin': 'f50/zerotier-ui',
            'url': 'https://github.com/yjy116/f50-daede-kernel',
            'depends': ['luci-base', 'rpcd-mod-file', 'zerotier=1.16.0_p2-r1']}


def stage_files(destination):
    shutil.copytree(HERE / 'root', destination)
    payload = sorted('/' + path.relative_to(destination).as_posix()
                     for path in destination.rglob('*') if path.is_file())
    listing = destination / f'lib/apk/packages/{PACKAGE_NAME}.list'
    listing.parent.mkdir(parents=True, exist_ok=True)
    listing.write_text('\n'.join(payload) + '\n', encoding='utf-8')
    for path in [destination, *destination.rglob('*')]:
        require(not path.is_symlink(), f'Unreviewed payload symlink: {path}')
        path.chmod(DIRECTORY_MODE if path.is_dir() else FILE_MODE)
    return snapshot_files(destination)


def snapshot_files(directory):
    files, directories = {}, {}
    for path in [directory, *sorted(directory.rglob('*'))]:
        name = '' if path == directory else path.relative_to(directory).as_posix()
        stat = path.stat()
        acl = {'mode': stat.st_mode & 0o7777, 'user': 'root', 'group': 'root'}
        if path.is_dir():
            directories[name] = acl
            continue
        files[name] = dict(acl, size=stat.st_size, mtime=int(stat.st_mtime), type='regular',
                           sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    return {'files': files, 'directories': directories}


def lifecycle_scripts():
    install = (HERE / 'post-install.sh').read_bytes()
    upgrade = install.replace(b'#!/bin/sh\n', b'#!/bin/sh\nexport PKG_UPGRADE=1\n', 1)
    return {'post-install': install, 'post-upgrade': upgrade}


def audit_package(candidate, expected):
    for field in ('files', 'directories', 'scripts'):
        require(candidate[field] == expected[field], f'Unexpected {field} change')
    require(candidate['signature_blocks'] == 1, 'Expected one package signature')
    require(candidate['package_fields'] == {}, 'Unexpected package extensions')
    actual = {key: value for key, value in candidate['info'].items() if key not in DERIVED}
    require(actual == package_info(), 'Unexpected package metadata or dependency')
    total_size = sum(item['size'] for item in expected['files'].values())
    require(candidate['info']['installed-size'] == total_size, 'Installed size mismatch')
