"""Exact package contracts for fixed HomeProxy and the matching 1.12.25 core."""
import hashlib
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'packaging'))
from apk3 import require
from package_audit import read_config, verify_config_binding

UI_VERSION = '2026.09.30-r1'
CORE_VERSION = '1.12.25-r1'
DERIVED = {'hashes', 'installed-size', 'file-size'}


def package_specs():
    common = {'arch': 'noarch', 'license': 'GPL-2.0-only', 'version': UI_VERSION,
              'origin': 'f50/homeproxy-pkg', 'url': 'https://github.com/immortalwrt/luci'}
    ui = dict(common, name='luci-app-homeproxy',
              description='Fixed HomeProxy; F50 builtin detection; UDP process matching unavailable',
              depends=sorted(['luci-base', 'firewall4', 'ucode-mod-digest', 'ip-full',
                              'sing-box=' + CORE_VERSION]))
    zh = dict(common, name='luci-i18n-homeproxy-zh-cn', description='Chinese translation for F50 HomeProxy',
              depends=['luci-app-homeproxy=' + UI_VERSION])
    return [{'kind': 'ui', 'info': ui}, {'kind': 'i18n', 'info': zh}]


def core_info(source, delta):
    require(source['name'] == 'sing-box' and source['version'] == '1.13.21-r1', 'Unexpected carrier')
    require(source['depends'] == ['ca-bundle', 'kmod-inet-diag', 'kmod-tun', 'libc'], 'Dependency drift')
    return dict(source, version=CORE_VERSION, depends=['ca-bundle', 'libc'],
                description='Official sing-box 1.12.25 ARM64 core for fixed HomeProxy; F50 TUN builtin; UDP process matching unavailable',
                origin='f50/homeproxy-pkg', **{'installed-size': source['installed-size'] + delta})


def verify_kernel(content, report):
    require(report.get('status') == 'PASS', 'Kernel report must pass')
    require(report.get('kernel', {}).get('release') == '7.2.8-f50-dae1', 'Unexpected kernel release')
    binding = verify_config_binding(report, content)
    config = read_config(content)
    required = ['CONFIG_TUN', 'CONFIG_NFT_TPROXY', 'CONFIG_INET_TCP_DIAG']
    require(all(config.get(k) == 'y' for k in required), 'Required builtins missing')
    return {'binding': binding, 'builtins': {k: config[k] for k in required},
            'optional_diagnostics': {k: config.get(k, 'n') for k in
                                     ['CONFIG_INET_UDP_DIAG', 'CONFIG_INET_RAW_DIAG']},
            'limitation': 'UDP process/path/UID matching unavailable; raw sockets are not queried.'}


def snapshot(root):
    files, directories = {}, {}
    for path in [root, *sorted(root.rglob('*'))]:
        require(not path.is_symlink(), 'Unexpected symlink')
        name = '' if path == root else path.relative_to(root).as_posix()
        status = path.stat()
        acl = {'mode': status.st_mode & 0o7777, 'user': 'root', 'group': 'root'}
        if path.is_dir():
            directories[name] = acl
        else:
            require(path.is_file(), 'Unexpected file type')
            files[name] = dict(acl, type='regular', size=status.st_size, mtime=int(status.st_mtime),
                               sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    return {'files': files, 'directories': directories}


def audit_package(candidate, expected, info):
    for field in ('files', 'directories', 'scripts'):
        require(candidate[field] == expected[field], f'Unexpected {field} change')
    require(candidate['signature_blocks'] == 1 and candidate['package_fields'] == {}, 'Signature/extensions drift')
    actual = {k: v for k, v in candidate['info'].items() if k not in DERIVED}
    require(actual == {k: v for k, v in info.items() if k not in DERIVED}, 'Metadata drift')
    require(candidate['info']['installed-size'] == sum(f['size'] for f in expected['files'].values()),
            'Installed size mismatch')
