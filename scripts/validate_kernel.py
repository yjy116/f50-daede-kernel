#!/usr/bin/env python3
"""Validate real ARM64 kernel artifacts; requires pahole, modinfo and build tools."""
import argparse
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
from pathlib import Path

KERNEL_VERSIONS = ('6.18.54', '7.2.8')
LOCAL_VERSION = '-f50-dae1'
HASH_CHUNK_BYTES = 1024 * 1024
TOOL_TIMEOUT_SECONDS = 60
ELF_HEADER = struct.Struct('<16sHHIQQQIHHHHHH')
SECTION_HEADER = struct.Struct('<IIQQQQIIQQ')
EM_AARCH64, ET_EXEC, ET_REL, ET_DYN = 183, 2, 1, 3
ELF_TYPE_NAMES = {ET_EXEC: 'ET_EXEC', ET_REL: 'ET_REL', ET_DYN: 'ET_DYN'}
SHN_XINDEX, SHT_NULL, SHT_NOBITS = 65535, 0, 8
EXPECTED_MODULES = frozenset('''mali_kbase sblock_bridge sbuf_bridge seth sipa-core
sipa-dele sipa-sys sipa_eth sipc-core sipx slog_bridge spipe spool sprd-sipc-virt-bus
sprd_modem_loader sprd_pmic_wdt sprd_power_manager sprd_shm sprd_systimer
sprd_time_sync sprd_time_sync_cp sprd_wlan_combo sprdbt_tty trusty-ipc trusty-irq
trusty-log trusty-pm trusty-virtio trusty unisoc-mailbox wcn_bsp'''.split())
TOOLS = ('pahole', 'modinfo', 'gcc', 'ld', 'strip', 'make')
BTF_MEMBERS = {'task_struct': ('mm',), 'mm_struct': ('arg_start',), 'bpf_prog': ()}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def run_tool(arguments):
    env = dict(os.environ, LC_ALL='C', LANG='C')
    result = subprocess.run(arguments, capture_output=True, text=True, env=env,
                            timeout=TOOL_TIMEOUT_SECONDS, check=False)
    require(result.returncode == 0, f'{arguments!r} exited {result.returncode}: '
            f'\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}')
    if result.stderr.strip():
        print(f'{arguments[0]} diagnostic: {result.stderr.strip()}', file=sys.stderr)
    return result.stdout.strip()


def read_config(path):
    values = {}
    for number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
        match = re.fullmatch(r'(CONFIG_[A-Z0-9_]+)=(.+)', line)
        disabled = re.fullmatch(r'# (CONFIG_[A-Z0-9_]+) is not set', line)
        if not match and not disabled:
            require(not line.strip() or line.startswith('#'), f'{path}:{number}: invalid config line')
            continue
        key, value = (match[1], match[2]) if match else (disabled[1], 'n')
        require(key not in values, f'{path}:{number}: duplicate {key}')
        values[key] = value
    require(bool(values), f'{path}: empty configuration')
    return values


def verify_config(paths):
    requested = read_config(paths.config_extra)
    actual = read_config(paths.build_dir / '.config')
    mismatches = {key: {'requested': value, 'actual': actual.get(key, '<missing>')}
                  for key, value in requested.items() if actual.get(key) != value}
    require(not mismatches, 'Final .config did not satisfy requests: ' + json.dumps(mismatches))
    require(actual.get('CONFIG_LOCALVERSION') == json.dumps(LOCAL_VERSION), 'Wrong LOCALVERSION')
    require(actual.get('CONFIG_LOCALVERSION_AUTO') == 'n', 'LOCALVERSION_AUTO must be explicitly off')
    return {'requested_values': requested, 'matched_count': len(requested),
            'compiler_config': actual.get('CONFIG_CC_VERSION_TEXT', '<missing>')}


def read_range(stream, offset, size):
    stream.seek(offset)
    data = stream.read(size)
    require(len(data) == size, f'Truncated ELF range: offset={offset}, size={size}')
    return data


def read_sections(stream, header):
    section_offset, entry_size, count, names_index = header[6], header[11], header[12], header[13]
    require(section_offset > 0 and entry_size == SECTION_HEADER.size, 'Invalid ELF section table')
    first = SECTION_HEADER.unpack(read_range(stream, section_offset, entry_size))
    count = count or first[5]
    names_index = first[6] if names_index == SHN_XINDEX else names_index
    require(count > 0 and names_index < count, 'Invalid ELF section count/string table')
    rows = [SECTION_HEADER.unpack(read_range(stream, section_offset + index * entry_size, entry_size))
            for index in range(count)]
    names_row = rows[names_index]
    names = read_range(stream, names_row[4], names_row[5])
    result = {}
    for row in rows:
        if row[1] == SHT_NULL:
            continue
        require(row[0] < len(names), 'Invalid section name offset')
        end = names.find(b'\0', row[0])
        require(end >= 0, 'Unterminated ELF section name')
        name = names[row[0]:end].decode('utf-8')
        require(name not in result, f'Duplicate ELF section {name}')
        result[name] = {'offset': row[4], 'size': row[5], 'type': row[1]}
    return result


def inspect_elf(path, expected_type):
    with path.open('rb') as stream:
        header = ELF_HEADER.unpack(read_range(stream, 0, ELF_HEADER.size))
        require(header[0].startswith(b'\x7fELF\x02\x01'), f'{path}: not little-endian ELF64')
        require(header[2] == EM_AARCH64, f'{path}: machine {header[2]}, expected AArch64')
        require(header[1] == expected_type,
                f'{path}: wrong ELF type {header[1]}, expected {expected_type}')
        sections = read_sections(stream, header)
    length = path.stat().st_size
    for name, section in sections.items():
        require(section['type'] == SHT_NOBITS or section['offset'] + section['size'] <= length,
                f'{path}: {name} extends past EOF')
    return sections, {'type': header[1], 'type_name': ELF_TYPE_NAMES[header[1]],
                      'machine': header[2]}


def file_record(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(HASH_CHUNK_BYTES), b''):
            digest.update(block)
    return {'path': str(path), 'size': path.stat().st_size, 'sha256': digest.hexdigest()}


def verify_btf(path, section):
    require(section and section['size'] > 0, f'{path}: .BTF missing or empty')
    results = {}
    for type_name, members in BTF_MEMBERS.items():
        command = ['pahole', '-F', 'btf', '-C', type_name, str(path)]
        output = run_tool(command)
        require(re.search(r'\bstruct\s+' + type_name + r'\s*\{', output),
                f'pahole did not decode struct {type_name} from BTF')
        for member in members:
            require(re.search(r'\b' + member + r'\s*;', output),
                    f'BTF struct {type_name} lacks required member {member}')
        results[type_name] = {'command': command, 'decoded': True,
                              'required_members': list(members),
                              'output_sha256': hashlib.sha256(output.encode()).hexdigest()}
    return results


def extract_btf(path, section, output):
    target = output.parent / 'vmlinux.btf'
    target.parent.mkdir(parents=True, exist_ok=True)
    with path.open('rb') as stream:
        data = read_range(stream, section['offset'], section['size'])
    temporary = target.with_suffix('.btf.tmp')
    temporary.write_bytes(data)
    temporary.replace(target)
    return file_record(target)


def kernel_elf_type(config):
    require(config.get('CONFIG_ARM64') == 'y', 'Kernel .config must identify ARM64')
    relocatable = config.get('CONFIG_RELOCATABLE')
    require(relocatable in ('y', 'n'), 'CONFIG_RELOCATABLE must be explicitly y or n')
    # Both pinned ARM64 Makefiles add -shared only for CONFIG_RELOCATABLE=y.
    return ET_DYN if relocatable == 'y' else ET_EXEC


def verify_kernel(paths, expected_release):
    release_file = paths.build_dir / 'include/config/kernel.release'
    require(release_file.read_text().strip() == expected_release, 'Generated kernel.release mismatch')
    kernel = paths.build_dir / 'vmlinux'
    actual_config = read_config(paths.build_dir / '.config')
    sections, elf_header = inspect_elf(kernel, kernel_elf_type(actual_config))
    require('.rodata' in sections, 'vmlinux has no .rodata for banner verification')
    with kernel.open('rb') as stream:
        rodata = sections['.rodata']
        banner = read_range(stream, rodata['offset'], rodata['size'])
    match = re.search(rb'Linux version ([^\s\x00]+) ', banner)
    require(match and match[1].decode() == expected_release, 'vmlinux Linux version banner mismatch')
    btf = sections.get('.BTF')
    decoded = verify_btf(kernel, btf)
    detached = extract_btf(kernel, btf, paths.output)
    return {'release': expected_release, 'elf_machine': 'AArch64', 'elf_header': elf_header,
            'config_relocatable': actual_config['CONFIG_RELOCATABLE'], 'btf_section': btf,
            'btf_type_checks': decoded, 'detached_btf': detached}


def verify_modules(directory, expected_release):
    modules = sorted(directory.glob('*.ko'))
    names = {path.stem for path in modules}
    require(names == EXPECTED_MODULES, f'Module manifest mismatch: '
            f'missing={sorted(EXPECTED_MODULES - names)}, extra={sorted(names - EXPECTED_MODULES)}')
    results, all_vermagic = [], set()
    for path in modules:
        sections, elf_header = inspect_elf(path, ET_REL)
        require(not any(name.startswith(('.debug', '.zdebug')) for name in sections),
                f'{path}: DWARF remains; validate after strip --strip-debug')
        for name in ('.modinfo', '.symtab'):
            require(sections.get(name, {}).get('size', 0) > 0, f'{path}: missing {name}')
        vermagic = run_tool(['modinfo', '-F', 'vermagic', str(path)])
        require(vermagic.split() and vermagic.split()[0] == expected_release,
                f'{path}: wrong vermagic {vermagic!r}')
        all_vermagic.add(vermagic)
        results.append(dict(file_record(path), elf_machine='AArch64',
                            elf_header=elf_header, vermagic=vermagic))
    require(len(all_vermagic) == 1, f'Module vermagic flags disagree: {sorted(all_vermagic)}')
    return results


def tool_versions():
    versions = {name: run_tool([name, '--version']) for name in TOOLS}
    version = re.search(r'(\d+)\.(\d+)', versions['pahole'])
    require(version and tuple(map(int, version.groups())) >= (1, 22), 'pahole >= 1.22 is required')
    return dict(versions, python=sys.version)


def build_report(paths):
    release = paths.kernel_version + LOCAL_VERSION
    tools = tool_versions()
    config = verify_config(paths)
    kernel = verify_kernel(paths, release)
    modules = verify_modules(paths.module_dir, release)
    names = ('.config', 'vmlinux', 'arch/arm64/boot/Image', 'System.map', 'Module.symvers',
             'include/config/kernel.release', 'modules.builtin', 'modules.builtin.modinfo')
    artifacts = [file_record(paths.build_dir / name) for name in names]
    return {'status': 'PASS', 'kernel': kernel, 'config': config, 'modules': modules,
            'module_count': len(modules), 'module_btf_required_by_dae': False,
            'config_extra': file_record(paths.config_extra), 'artifacts': artifacts,
            'tool_versions': tools, 'runtime_boot_verified': False}


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel-version', required=True, choices=KERNEL_VERSIONS)
    for name in ('build-dir', 'module-dir', 'config-extra', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    return parser.parse_args()


def main():
    paths = parse_args()
    try:
        report = build_report(paths)
        exit_code = 0
    except (OSError, ValueError, subprocess.SubprocessError, struct.error) as error:
        report = {'status': 'FAIL', 'error': str(error), 'kernel_version': paths.kernel_version,
                  'runtime_boot_verified': False}
        exit_code = 1
    paths.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = paths.output.with_suffix(paths.output.suffix + '.tmp')
    temporary.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    temporary.replace(paths.output)
    print(json.dumps({'status': report['status'], 'output': str(paths.output),
                      'error': report.get('error')}, indent=2))
    return exit_code


if __name__ == '__main__':
    raise SystemExit(main())
