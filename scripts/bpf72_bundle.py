#!/usr/bin/env python3
"""Check pinned MU300 module inventory and the bytes emitted by its packager."""
import argparse
import hashlib
import json
import re
import struct
import tarfile
from pathlib import Path, PurePosixPath

from validate_kernel import module_identity

REFERENCE_MODULE_COUNT = 376
REFERENCE_RELEASE = '7.2.9'
# The pinned release stores these names with the opposite-case module payload.
REFERENCE_CASE_COLLISIONS = {'xt_dscp': 'xt_DSCP', 'xt_HL': 'xt_hl', 'xt_tcpmss': 'xt_TCPMSS'}
CANDIDATE_MODULE_COUNT = REFERENCE_MODULE_COUNT + len(REFERENCE_CASE_COLLISIONS)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def archive_files(archive):
    result = {}
    for member in archive.getmembers():
        name = str(PurePosixPath(member.name))
        require(not name.startswith('/') and '..' not in PurePosixPath(name).parts,
                f'Unsafe archive path: {name}')
        if member.isdir():
            continue
        require(member.isfile(), f'Non-file bundle member: {name}')
        require(name not in result, f'Duplicate archive path: {name}')
        result[name] = archive.extractfile(member).read()
    return result


def module_names(files, expected_count):
    names = []
    for path in files:
        if not path.startswith('modules/'):
            continue
        require(re.fullmatch(r'modules/[A-Za-z0-9_-]+\.ko', path),
                f'Invalid module path: {path}')
        names.append(Path(path).stem)
    aliases = [name.replace('-', '_') for name in names]
    require(len(set(aliases)) == len(aliases), 'Module hyphen/underscore alias collision')
    require(len(names) == expected_count, f'Expected {expected_count} modules, found {len(names)}')
    return sorted(names)


def reference_inventory(files):
    names = module_names(files, REFERENCE_MODULE_COUNT)
    repairs = []
    for name in names:
        internal = module_identity(files[f'modules/{name}.ko'])
        expected = REFERENCE_CASE_COLLISIONS.get(name, name.replace('-', '_'))
        require(internal == expected, f'Reference module identity mismatch: {name}: {internal}')
        if name in REFERENCE_CASE_COLLISIONS:
            repairs.append({'filename': name, 'internal_name': internal})
    require(len(repairs) == len(REFERENCE_CASE_COLLISIONS), 'Missing pinned case collisions')
    require(not set(REFERENCE_CASE_COLLISIONS.values()) & set(names),
            'Reference case-collision inventory changed')
    corrected = sorted(set(names) | set(REFERENCE_CASE_COLLISIONS.values()))
    return {'module_names': corrected, 'module_count': len(corrected),
            'reference_module_names': names, 'reference_module_count': len(names),
            'reference_case_collisions': repairs}


def metadata(files, release):
    require(files.get('kernel.release', b'').decode().strip() == release,
            'kernel.release does not match expected version')
    require('f50' in files.get('devices', b'').decode().split(), 'devices lacks f50')
    require({'sdcard', 'linux-slot'} <= set(files.get('features', b'').decode().split()),
            'features lacks sdcard or linux-slot')
    for name in ('Image', 'ramdisk-generic.lz4'):
        require(bool(files.get(name)), f'{name} missing or empty')
    ramdisk = files['ramdisk-generic.lz4']
    details = json.loads(files.get('ramdisk-generic.json', b'{}'))
    require(details.get('size') == len(ramdisk) and details.get('sha256') == digest(ramdisk),
            'ramdisk metadata does not match actual bytes')
    return {'image_sha256': digest(files['Image']), 'ramdisk': details}


def prepare(options):
    with tarfile.open(options.bundle, 'r:gz') as archive:
        files = archive_files(archive)
    evidence = metadata(files, REFERENCE_RELEASE)
    inventory = reference_inventory(files)
    return dict(evidence, status='PASS', kernel_release=REFERENCE_RELEASE,
                reference_sha256=digest(options.bundle.read_bytes()),
                **inventory, runtime_boot_verified=False)


def reference_names(path):
    reference = json.loads(path.read_text(encoding='utf-8'))
    require(reference.get('status') == 'PASS', 'Reference manifest was not verified')
    names = reference.get('module_names', [])
    require(isinstance(names, list) and len(names) == CANDIDATE_MODULE_COUNT,
            f'Reference manifest must contain {CANDIDATE_MODULE_COUNT} module names')
    require(all(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9_-]+', name)
                for name in names), 'Invalid reference module name')
    require(len(set(names)) == len(names), 'Duplicate reference module name')
    require(reference.get('kernel_release') == REFERENCE_RELEASE,
            'Reference kernel.release does not match pinned version')
    require(re.fullmatch(r'[0-9a-f]{64}', reference.get('reference_sha256', '')),
            'Invalid reference SHA256')
    original = reference.get('reference_module_names', [])
    require(len(original) == REFERENCE_MODULE_COUNT and len(set(original)) == len(original),
            'Reference original inventory must have 376 unique module names')
    require(set(names) == set(original) | set(REFERENCE_CASE_COLLISIONS.values()),
            'Candidate inventory must differ by exactly the three case-collision repairs')
    expected = [{'filename': name, 'internal_name': value}
                for name, value in sorted(REFERENCE_CASE_COLLISIONS.items())]
    require(reference.get('reference_case_collisions') == expected,
            'Missing verified reference case-collision evidence')
    return reference


def source_modules(directory):
    return {path.stem: path for path in directory.glob('*.ko')}


def verify(options):
    reference = reference_names(options.reference)
    with tarfile.open(options.bundle, 'r:gz') as archive:
        files = archive_files(archive)
    evidence = metadata(files, options.kernel_release)
    names = module_names(files, CANDIDATE_MODULE_COUNT)
    require(names == sorted(reference['module_names']), 'Packaged module inventory changed')
    sources = source_modules(options.module_dir)
    require(set(sources) == set(names), 'Source module inventory differs from reference')
    modules = []
    for name in names:
        packaged = files[f'modules/{name}.ko']
        require(digest(packaged) == digest(sources[name].read_bytes()),
                f'Module SHA256 mismatch: {name}')
        internal = module_identity(packaged)
        require(internal == name.replace('-', '_'), f'Module internal name mismatch: {name}: {internal}')
        modules.append({'name': name, 'internal_name': internal,
                        'sha256': digest(packaged), 'size': len(packaged)})
    return dict(evidence, status='PASS', kernel_release=options.kernel_release,
                reference_sha256=reference['reference_sha256'], module_names=names,
                module_count=len(names), modules=modules, runtime_boot_verified=False,
                bundle_sha256=digest(options.bundle.read_bytes()))


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    operations = parser.add_subparsers(dest='operation', required=True)
    for name in ('prepare-reference', 'verify'):
        operation = operations.add_parser(name)
        operation.add_argument('--bundle', type=Path, required=True)
        operation.add_argument('--output', type=Path, required=True)
        if name == 'verify':
            operation.add_argument('--reference', type=Path, required=True)
            operation.add_argument('--module-dir', type=Path, required=True)
            operation.add_argument('--kernel-release', required=True)
    return parser.parse_args()


def main():
    options = parse_args()
    try:
        report = prepare(options) if options.operation == 'prepare-reference' else verify(options)
    except (OSError, ValueError, KeyError, struct.error, tarfile.TarError) as error:
        report = {'status': 'FAIL', 'error': str(error), 'runtime_boot_verified': False}
    options.output.parent.mkdir(parents=True, exist_ok=True)
    options.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': report['status'], 'error': report.get('error')}))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
