"""Exact F50 OpenClash package, file and default-state contracts."""
import hashlib
from pathlib import Path, PurePosixPath
import shlex
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'packaging'))
from apk3 import require

UI_VERSION = '0.47.167-r1'
CORE_VERSION = '1.19.31-r1'
CORE_PATH = 'etc/openclash/core/clash_meta'
KERNEL_RELEASE = '7.2.8-f50-dae1'
DERIVED = {'hashes', 'installed-size', 'file-size'}


def information(name, options):
    info = {'name': name, 'version': options['version'], 'arch': options['arch'],
            'description': options['description'], 'license': options['license'],
            'origin': 'f50/openclash-pkg', 'url': options['url']}
    return dict(info, depends=sorted(options['depends'])) if options['depends'] else info


def package_specs():
    ui = information('luci-app-openclash', {
        'version': UI_VERSION, 'arch': 'noarch', 'license': 'MIT',
        'description': 'OpenClash 0.47.167 from fixed source; F50 builtin TUN/NFT_TPROXY',
        'url': 'https://github.com/vernesong/OpenClash',
        'depends': ['luci-base', 'luci-compat', 'rpcd-mod-file', 'dnsmasq-full', 'bash',
                    'curl', 'ca-bundle', 'ip-full', 'ruby', 'ruby-yaml', 'unzip',
                    'mihomo-openclash=' + CORE_VERSION]})
    core = information('mihomo-openclash', {
        'version': CORE_VERSION, 'arch': 'aarch64_generic', 'license': 'GPL-3.0-only',
        'description': 'Official Mihomo v1.19.31 ARM64 core for OpenClash; no init service',
        'url': 'https://github.com/MetaCubeX/mihomo', 'depends': []})
    return [{'kind': 'ui', 'info': ui}, {'kind': 'core', 'info': core}]


def snapshot(root):
    files, directories = {}, {}
    for path in [root, *sorted(root.rglob('*'))]:
        require(not path.is_symlink(), f'Unreviewed symlink: {path}')
        name = '' if path == root else path.relative_to(root).as_posix()
        status = path.stat()
        common = {'mode': status.st_mode & 0o7777, 'user': 'root', 'group': 'root'}
        if path.is_dir():
            directories[name] = common
        else:
            require(path.is_file(), f'Unsupported payload object: {name}')
            files[name] = dict(common, size=status.st_size, mtime=int(status.st_mtime),
                               type='regular', sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    return {'files': files, 'directories': directories}


def audit_package(candidate, expected, info):
    for field in ('files', 'directories', 'scripts'):
        require(candidate[field] == expected[field], f'Unexpected {field} drift')
    require(candidate['signature_blocks'] == 1, 'Expected one signature')
    require(candidate['package_fields'] == {}, 'Unexpected package extensions')
    actual = {key: value for key, value in candidate['info'].items() if key not in DERIVED}
    require(actual == info, f'Unexpected metadata: actual={actual!r}; expected={info!r}')
    size = sum(row['size'] for row in expected['files'].values())
    require(candidate['info']['installed-size'] == size, 'Installed size mismatch')


def validate_member(member, prefix):
    path = PurePosixPath(member.name)
    require(not path.is_absolute() and '..' not in path.parts, 'Unsafe source path')
    require(member.name.startswith(prefix), 'Unexpected source prefix')
    require(member.isfile() or member.isdir(), 'Source links/special objects are not permitted')
    relative = member.name[len(prefix):]
    require(relative and not PurePosixPath(relative).is_absolute(), 'Empty/absolute source path')
    return relative


def verify_disabled(content):
    current, values = None, []
    for line in content.splitlines():
        words = shlex.split(line, comments=True)
        if not words:
            continue
        if words[0] == 'config':
            current = words[1:]
        if current == ['openclash', 'config'] and words[:2] == ['option', 'enable']:
            values.append(words[2:])
    require(values == [['0']], 'OpenClash default must be explicitly disabled exactly once')


def verify_elf(evidence):
    require('AArch64' in evidence['header'], 'Core must be AArch64')
    require('INTERP' not in evidence['program'], 'Core has a dynamic interpreter')
    require('NEEDED' not in evidence['dynamic'], 'Core has shared-library dependencies')


def verify_kernel(config, report):
    require(report.get('status') == 'PASS', 'Kernel validation report must have PASS status')
    require(report.get('kernel', {}).get('release') == KERNEL_RELEASE, 'Kernel release mismatch')
    checksum = hashlib.sha256(config).hexdigest()
    matches = [r for r in report['artifacts'] if r['path'].endswith('/.config')]
    require(len(matches) == 1 and matches[0]['sha256'] == checksum, 'Kernel evidence mismatch')
    values = dict(line.split('=', 1) for line in config.decode().splitlines()
                  if line.startswith('CONFIG_') and '=' in line)
    required = ['CONFIG_TUN', 'CONFIG_NFT_TPROXY']
    require(all(values.get(name) == 'y' for name in required), 'Required F50 kernel feature not builtin')
    diagnostic = ['CONFIG_INET_DIAG', 'CONFIG_INET_TCP_DIAG', 'CONFIG_INET_UDP_DIAG', 'CONFIG_INET_RAW_DIAG']
    return {'sha256': checksum, 'release': KERNEL_RELEASE, 'validation_status': 'PASS',
            'required_builtin': {k: values[k] for k in required},
            'optional_process_lookup': {k: values.get(k, 'not set') for k in diagnostic},
            'limitation': 'Missing UDP_DIAG prevents UDP process/UID lookup; no fake kmod provider.'}
