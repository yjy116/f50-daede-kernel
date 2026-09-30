#!/usr/bin/env python3
"""Apply the pinned upstream RX checksum fix to the mainline module source tree."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

UPSTREAM_COMMIT = '1a69a41ea9d20fadd575e9b082364d61ce5fcf9a'
PATCH_RELATIVE = Path('kernel/patches/wlan_combo-rx-software-checksum.patch')
SOURCE_RELATIVE = Path('sc2355/rx.c')
PATCH_SHA256 = 'a9b58f399781aa204550c1ff9829eb83c8db7193c0e40c5428c784572dd528cc'
BEFORE_SHA256 = 'de78047e7eac6c5b0e8dc68e0152359435b9d2e63a27bff5b845103eadf0dddb'
AFTER_SHA256 = 'e15b3fd5e668fa247951601331759c9d73cbb4ed66bbe3e206c64a186794aa8e'
PATCH_TIMEOUT_SECONDS = 30


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_git_apply(module, patch, check):
    args = ['git', '-c', 'core.autocrlf=false', '-c', 'core.eol=lf',
            'apply', '--whitespace=error-all']
    if check:
        args.append('--check')
    result = subprocess.run([*args, str(patch)], cwd=module, capture_output=True,
                            text=True, check=False, timeout=PATCH_TIMEOUT_SECONDS)
    require(result.returncode == 0, f'WLAN git apply check={check} failed '
            f'({result.returncode}): {result.stdout}\n{result.stderr}')
    return result.returncode


def apply_source_patch(options):
    patch = (options.source_root / PATCH_RELATIVE).resolve()
    source = (options.module_dir / SOURCE_RELATIVE).resolve()
    require(digest(patch) == PATCH_SHA256, 'Upstream WLAN patch hash mismatch')
    require(digest(source) == BEFORE_SHA256, 'Unpatched WLAN source hash mismatch')
    checked = run_git_apply(options.module_dir, patch, True)
    applied = run_git_apply(options.module_dir, patch, False)
    require(digest(source) == AFTER_SHA256, 'Patched WLAN source hash mismatch')
    options.output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(patch, options.output.parent / PATCH_RELATIVE.name)
    shutil.copyfile(source, options.output.parent / 'wlan-rx-patched.c')
    return {'status': 'PASS', 'upstream_commit': UPSTREAM_COMMIT,
            'patch_path': PATCH_RELATIVE.as_posix(), 'patch_sha256': PATCH_SHA256,
            'module_source': str(source), 'before_sha256': BEFORE_SHA256,
            'after_sha256': AFTER_SHA256, 'git_apply_check_exit': checked,
            'git_apply_exit': applied, 'runtime_boot_verified': False,
            'panic_fix_verified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['apply'])
    for name in ('source-root', 'module-dir', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    options = parser.parse_args()
    report = apply_source_patch(options)
    options.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
