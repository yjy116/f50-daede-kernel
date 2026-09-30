#!/usr/bin/env python3
"""Verify the final ARM64 WLAN helper clears the real skb checksum field."""
import argparse
import json
from pathlib import Path
import re
import subprocess

from validate_kernel import ET_REL, file_record, inspect_elf, require, run_tool
from wlan_rx_checksum import AFTER_SHA256, PATCH_SHA256, digest

HELPER = 'sc2355_fill_skb_csum'
CHECKSUM_FIELD_BITS = 2
BYTE_BITS = 8
BYTE_MASK = (1 << BYTE_BITS) - 1
EXPECTED_INSTRUCTIONS = 5
ARM64_ZERO_REGISTER = 31
INTEGER = r'(?:0x[0-9a-f]+|[0-9]+)'


def checksum_layout(layout):
    pattern = r'\bip_summed\s*:\s*2\s*;\s*/\*\s*(\d+)\s*:\s*(\d+)\s+\d+\s*\*/'
    matches = re.findall(pattern, layout)
    require(len(matches) == 1, 'Cannot identify the real sk_buff.ip_summed BTF layout')
    offset, bit = map(int, matches[0])
    require(bit + CHECKSUM_FIELD_BITS <= BYTE_BITS, 'Checksum field crosses a byte')
    return offset, bit


def helper_instructions(assembly):
    require(f'<{HELPER}>:' in assembly, f'Final module lacks {HELPER} disassembly')
    instructions = re.findall(r'^\s*[0-9a-f]+:\s+(\S.*)$', assembly, re.MULTILINE)
    normalized = [re.sub(r'\s+', '', line.split('//')[0]) for line in instructions]
    core = [line for line in normalized if line not in ('btic', 'nop')]
    require(len(core) == EXPECTED_INSTRUCTIONS,
            f'Unexpected checksum helper instructions; inspect actual disassembly: {core}')
    return core


def verify_software_checksum(assembly, layout):
    offset, bit = checksum_layout(layout)
    load, mask, store, zero, ret = helper_instructions(assembly)
    match = re.fullmatch(r'ldrbw(\d+),\[x0(?:,#(' + INTEGER + r'))?\]', load)
    require(match is not None, 'Checksum helper does not load one skb byte')
    register, location = match[1], int(match[2] or '0', 0)
    require(0 < int(register) < ARM64_ZERO_REGISTER,
            'Checksum helper must preserve the skb pointer and loaded byte')
    require(location == offset, 'Checksum helper loads the wrong skb field')
    require(store == load.replace('ldrb', 'strb', 1), 'Checksum helper store targets another field')
    match = re.fullmatch(r'andw' + register + r',w' + register + r',#(' + INTEGER + ')', mask)
    require(match is not None, 'Checksum helper does not clear checksum bits with AND')
    expected_mask = BYTE_MASK ^ (((1 << CHECKSUM_FIELD_BITS) - 1) << bit)
    require(int(match[1], 0) & BYTE_MASK == expected_mask, 'Checksum helper uses the wrong bit mask')
    require(zero in ('movw0,#0', 'movw0,#0x0'), 'Checksum helper does not return zero')
    require(ret in ('ret', 'retx30'), 'Checksum helper has an unexpected return')
    return {'function': HELPER, 'ip_summed_byte_offset': offset,
            'ip_summed_bit_offset': bit, 'checksum_none_mask': expected_mask,
            'instructions': [load, mask, store, zero, ret],
            'software_checksum_path': True}


def verify_artifacts(options):
    report = json.loads(options.source_report.read_text(encoding='utf-8'))
    require(report.get('status') == 'PASS' and report.get('patch_sha256') == PATCH_SHA256,
            'Missing verified upstream WLAN patch report')
    require(report.get('after_sha256') == AFTER_SHA256, 'Unexpected patched source report')
    require(digest(options.compiled_source) == AFTER_SHA256,
            'The vendor build copied a different WLAN source')
    inspect_elf(options.module, ET_REL)
    assembly = run_tool(['objdump', '-d', '--no-show-raw-insn',
                         '--disassemble=' + HELPER, str(options.module)])
    layout = run_tool(['pahole', '-F', 'btf', '-C', 'sk_buff', str(options.kernel)])
    options.output.parent.mkdir(parents=True, exist_ok=True)
    (options.output.parent / 'wlan-rx-helper.disasm').write_text(assembly + '\n', encoding='utf-8')
    (options.output.parent / 'wlan-skb-layout.txt').write_text(layout + '\n', encoding='utf-8')
    return {'status': 'PASS', 'proof': verify_software_checksum(assembly, layout),
            'module': file_record(options.module), 'source': file_record(options.compiled_source),
            'source_report': file_record(options.source_report),
            'runtime_boot_verified': False, 'panic_fix_verified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('module', 'kernel', 'compiled-source', 'source-report', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    options = parser.parse_args()
    try:
        report = verify_artifacts(options)
        status = 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        report = {'status': 'FAIL', 'error': str(error), 'panic_fix_verified': False}
        status = 1
    options.output.parent.mkdir(parents=True, exist_ok=True)
    options.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))
    return status


if __name__ == '__main__':
    raise SystemExit(main())
