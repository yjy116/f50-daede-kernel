#!/usr/bin/env python3
"""Check pinned MU300 module inventory and the bytes emitted by its packager."""
import argparse
import hashlib
import json
import re
import tarfile
from pathlib import Path, PurePosixPath

MODULE_COUNT = 376
REFERENCE_RELEASE = '7.2.9'


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


def module_names(files):
    names = []
    for path in files:
        if not path.startswith('modules/'):
            continue
        require(re.fullmatch(r'modules/[A-Za-z0-9_-]+\.ko', path),
                f'Invalid module path: {path}')
        names.append(Path(path).stem)
    aliases = [name.replace('-', '_') for name in names]
    require(len(set(aliases)) == len(aliases), 'Module hyphen/underscore alias collision')
    require(len(names) == MODULE_COUNT, f'Expected {MODULE_COUNT} modules, found {len(names)}')
    return sorted(names)


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
    names = module_names(files)
    return dict(evidence, status='PASS', kernel_release=REFERENCE_RELEASE,
                reference_sha256=digest(options.bundle.read_bytes()),
                module_names=names, module_count=len(names), runtime_boot_verified=False)


def reference_names(path):
    reference = json.loads(path.read_text(encoding='utf-8'))
    require(reference.get('status') == 'PASS', 'Reference manifest was not verified')
    names = reference.get('module_names', [])
    require(isinstance(names, list) and len(names) == MODULE_COUNT,
            f'Reference manifest must contain {MODULE_COUNT} module names')
    require(all(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9_-]+', name)
                for name in names), 'Invalid reference module name')
    require(len(set(names)) == len(names), 'Duplicate reference module name')
    require(reference.get('kernel_release') == REFERENCE_RELEASE,
            'Reference kernel.release does not match pinned version')
    require(re.fullmatch(r'[0-9a-f]{64}', reference.get('reference_sha256', '')),
            'Invalid reference SHA256')
    return reference


def verify(options):
    reference = reference_names(options.reference)
    with tarfile.open(options.bundle, 'r:gz') as archive:
        files = archive_files(archive)
    evidence = metadata(files, options.kernel_release)
    names = module_names(files)
    require(names == sorted(reference['module_names']), 'Packaged module inventory changed')
    sources = {path.stem: path for path in options.module_dir.glob('*.ko')}
    require(set(sources) == set(names), 'Source module inventory differs from reference')
    modules = []
    for name in names:
        packaged = files[f'modules/{name}.ko']
        require(digest(packaged) == digest(sources[name].read_bytes()),
                f'Module SHA256 mismatch: {name}')
        modules.append({'name': name, 'sha256': digest(packaged), 'size': len(packaged)})
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
    except (OSError, ValueError, KeyError, tarfile.TarError) as error:
        report = {'status': 'FAIL', 'error': str(error), 'runtime_boot_verified': False}
    options.output.parent.mkdir(parents=True, exist_ok=True)
    options.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': report['status'], 'error': report.get('error')}))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
