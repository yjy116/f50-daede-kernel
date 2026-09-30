"""Prepare pinned generic EasyTier core, patched LuCI and Chinese APKs in cloud."""
import argparse
import difflib
import json
import os
from pathlib import Path
import tempfile
import zipfile

from package_policy import INIT_PATH, audit_package, expected_info, verify_kernel
from patch_init import patch_init
from apk3 import read_package, require
from repack import (create_key, obtain_input, package_arguments, preserve_link_times,
                    publish, record, run, tool_versions)

HERE = Path(__file__).resolve().parent


def obtain_packages(settings, context):
    archive = obtain_input(settings['archive'], context['options'], context['temporary'])
    require(archive.stat().st_size == settings['archive']['size'], 'Archive size mismatch')
    result = {}
    with zipfile.ZipFile(archive) as source:
        names = source.namelist()
        require(len(names) == len(set(names)) and set(names) == set(settings['archive']['members']),
                'Unexpected archive member set')
        for spec in settings['packages']:
            path = context['temporary'] / spec['filename']
            path.write_bytes(source.read(spec['filename']))
            require(record(path)['sha256'] == spec['sha256'], 'Pinned member SHA256 mismatch')
            result[spec['name']] = path
    return result


def verify_source(path, spec):
    source = read_package(path)
    require(source['signature_blocks'] == 1, 'Unexpected source signature count')
    for field, value in (('name', spec['name']), ('version', spec['source_version']),
                         ('arch', spec['arch'])):
        require(source['info'][field] == value, f'Unexpected source {field}')
    return source


def modify_init(root, source, staging):
    path = root / INIT_PATH
    original = path.read_bytes()
    patched = patch_init(original)
    path.write_bytes(patched)
    timestamp = source['files'][INIT_PATH]['mtime']
    os.utime(path, (timestamp, timestamp))
    run(['bash', '-n', path])
    difference = ''.join(difflib.unified_diff(original.decode().splitlines(True),
                                            patched.decode().splitlines(True),
                                            fromfile='upstream/' + INIT_PATH,
                                            tofile='f50/' + INIT_PATH))
    (staging / 'easytier-init.diff').write_text(difference, encoding='utf-8')
    return {'patched_init': patched, 'init_size_delta': len(patched) - len(original)}


def adapt(spec, context):
    source_path = context['inputs'][spec['name']]
    source = verify_source(source_path, spec)
    run(['apk', 'version', '--check', spec['version']])
    require(run(['apk', 'version', '--test', spec['version'], spec['source_version']]) == '>',
            'Output version must compare newer than upstream')
    workspace = context['temporary'] / spec['name']
    root = workspace / 'root'
    root.mkdir(parents=True)
    root.chmod(source['directories']['']['mode'])
    run(['apk', 'extract', '--allow-untrusted', '--destination', root, source_path])
    preserve_link_times(root, source['files'])
    options = dict(spec)
    if spec['name'] == 'luci-app-easytier':
        options.update(modify_init(root, source, context['staging']))
    expected = expected_info(source['info'], options)
    output = context['staging'] / f"{spec['name']}-{spec['version']}-{spec['arch']}.apk"
    command = ['apk', 'mkpkg', '--compat', '3.0.0_pre1', '--compression', 'deflate:0',
               '--files', root, '--output', output, '--sign-key', context['private']]
    run(command + package_arguments(expected, source['scripts'], workspace))
    candidate = read_package(output)
    audit = audit_package(source, candidate, options)
    run(['apk', '--keys-dir', context['keys'], '--repositories-file', '/dev/null',
         '--no-network', 'verify', output])
    return {'input': record(source_path), 'output': record(output), 'audit': audit,
            'source_info': source['info'], 'adapted_info': candidate['info'],
            'signature_verified': True}


def build(options):
    require(not options.output.exists() or not any(options.output.iterdir()), 'Output must be empty')
    settings = json.loads((HERE / 'inputs.json').read_text())
    versions = tool_versions()
    kernel = verify_kernel(json.loads(options.kernel_validation.read_text()),
                           options.kernel_config.read_bytes())
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='f50-et-key-', dir='/dev/shm') as private_name:
        with tempfile.TemporaryDirectory(prefix='f50-et-') as temporary_name:
            temporary = Path(temporary_name)
            staging = temporary / 'publish'
            keys = staging / 'keys'
            keys.mkdir(parents=True)
            private = create_key(Path(private_name), keys)
            context = {'temporary': temporary, 'staging': staging, 'keys': keys,
                       'private': private, 'options': options}
            context['inputs'] = obtain_packages(settings, context)
            packages = [adapt(spec, context) for spec in settings['packages']]
            manifest = {'status': 'PASS', 'provenance': settings, 'packages': packages,
                        'kernel_evidence': dict(kernel, report=record(options.kernel_validation)),
                        'tool_versions': versions, 'public_key': record(keys / 'f50-packaging.pem'),
                        'packaging_sources': [record(p) for p in sorted(HERE.iterdir()) if p.is_file()],
                        'private_key_exported': False, 'upstream_signature_verified': False,
                        'device_runtime_tested_by_packager': False}
            publish(staging, options.output, manifest)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-dir', type=Path, help='Optional cache containing the exact ZIP')
    parser.add_argument('--kernel-validation', type=Path, required=True)
    parser.add_argument('--kernel-config', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    manifest = build(parser.parse_args())
    print(json.dumps({'status': manifest['status'], 'packages':
                      [p['output'] for p in manifest['packages']]}, indent=2))


if __name__ == '__main__':
    main()
