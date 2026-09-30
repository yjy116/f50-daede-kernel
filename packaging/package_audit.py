"""Explicit F50 metadata adaptation and invariants; no target-system operations."""
import hashlib
import re

from apk3 import require

REMOVED_DEPENDENCIES = {'daed': ('kmod-sched-bpf', 'kmod-sched-core', 'kmod-veth'),
                       'zerotier': ('kmod-tun',)}
BUILTIN_MAPPING = {
    'kmod-sched-bpf': ['CONFIG_BPF', 'CONFIG_BPF_SYSCALL', 'CONFIG_BPF_JIT',
                       'CONFIG_NET_CLS_BPF', 'CONFIG_NET_ACT_BPF'],
    'kmod-sched-core': ['CONFIG_NET_SCHED', 'CONFIG_NET_CLS_ACT',
                        'CONFIG_NET_SCH_INGRESS', 'CONFIG_NET_INGRESS', 'CONFIG_NET_EGRESS'],
    'kmod-veth': ['CONFIG_VETH'],
    'kmod-tun': ['CONFIG_TUN'],
}
ADDITIONAL_REQUIRED = ('CONFIG_DEBUG_INFO_BTF', 'CONFIG_CGROUP_BPF',
                       'CONFIG_NET_SOCK_MSG', 'CONFIG_BPF_STREAM_PARSER')
SUPPORTED_RELEASES = ('6.18.54-f50-dae1', '7.2.8-f50-dae1')


def expected_info(info, policy):
    dependencies = list(info['depends'])
    name = info['name']
    if name in REMOVED_DEPENDENCIES:
        removed = REMOVED_DEPENDENCIES[name]
        require(all(dependencies.count(dep) == 1 for dep in removed),
                'Source must contain exactly the reviewed kmod dependencies')
        dependencies = [dep for dep in dependencies if dep not in removed]
    else:
        require(name == 'luci-app-daede' and dependencies.count('daed') == 1,
                'Unreviewed LuCI dependency schema')
        dependencies = ['daed=' + policy['daed_version'] if dep == 'daed' else dep
                        for dep in dependencies]
    return dict(info, version=policy['version'], depends=dependencies,
                description=info['description'] + policy['description_suffix'])


def audit_repack(source, candidate, policy):
    for key in ('directories', 'files', 'scripts', 'package_fields'):
        require(source[key] == candidate[key], f'{key} changed during repack')
    require(candidate['signature_blocks'] == 1, 'Expected one package signature')
    expected = expected_info(source['info'], policy)
    actual = candidate['info']
    require({k: v for k, v in expected.items() if k != 'hashes'} ==
            {k: v for k, v in actual.items() if k != 'hashes'}, 'Unexpected metadata change')
    keys = source['info'].keys() | actual.keys()
    changes = {key: {'before': source['info'].get(key), 'after': actual.get(key)}
               for key in sorted(keys) if source['info'].get(key) != actual.get(key)}
    return {'payload_changes': [], 'lifecycle_script_changes': [],
            'metadata_changes': changes, 'files': candidate['files'],
            'directories': candidate['directories'],
            'scripts': {name: {'size': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
                        for name, body in candidate['scripts'].items()}}


def read_config(content):
    values = {}
    for line in content.decode('utf-8').splitlines():
        enabled = re.fullmatch(r'(CONFIG_[A-Z0-9_]+)=(.*)', line)
        disabled = re.fullmatch(r'# (CONFIG_[A-Z0-9_]+) is not set', line)
        if not enabled and not disabled:
            require(not line.strip() or line.startswith('#'), 'Invalid kernel config line')
            continue
        name, value = (enabled[1], enabled[2]) if enabled else (disabled[1], 'n')
        require(name not in values, f'Duplicate kernel config symbol: {name}')
        values[name] = value
    return values


def verify_config_binding(report, content):
    entries = [item for item in report.get('artifacts', [])
               if item.get('path', '').rsplit('/', 1)[-1] == '.config']
    require(len(entries) == 1, 'Kernel report must bind exactly one .config artifact')
    entry = entries[0]
    require(len(content) == entry['size'], 'Actual kernel config size mismatch')
    require(hashlib.sha256(content).hexdigest() == entry['sha256'], 'Actual kernel config SHA256 mismatch')
    return entry


def verify_kernel_evidence(report, actual_config):
    require(report.get('status') == 'PASS', 'Kernel validation must have passed')
    release = report.get('kernel', {}).get('release')
    require(release in SUPPORTED_RELEASES, 'Unsupported kernel release')
    binding = verify_config_binding(report, actual_config)
    config = read_config(actual_config)
    required = set(ADDITIONAL_REQUIRED).union(*BUILTIN_MAPPING.values())
    mismatches = {name: config.get(name, '<missing>') for name in required if config.get(name) != 'y'}
    require(not mismatches, f'Missing built-in capability evidence: {mismatches}')
    return {'release': release, 'builtin_mapping': BUILTIN_MAPPING, 'actual_config_artifact': binding,
            'verified_values': {name: config[name] for name in sorted(required)},
            'scope': 'dae-required paths plus ZeroTier TUN; not every kmod-sched-core algorithm',
            'runtime_verified_by_this_packager': False}


def verify_default_disabled(package):
    config = package['selected_contents'].get('etc/config/daed', b'')
    enabled = re.findall(rb'^\s*option\s+enabled\s+[\'\"]?([^\s\'\"]+)', config, re.M)
    require(enabled == [b'0'], 'Upstream daed default must remain disabled')
    return {'default_enabled': False, 'config_sha256': hashlib.sha256(config).hexdigest(),
            'existing_device_configuration_overridden': False}
