#!/usr/bin/env python3
"""Build an audited backend overlay while retaining the pinned ZeroTier binary."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

from package_model import HERE, VERSION, audit_package, expected_info, stage_files

sys.path.insert(0, str(HERE.parent / 'packaging'))
from apk3 import read_package, require
from package_audit import verify_kernel_evidence
from repack import (create_key, obtain_input, package_arguments, preserve_link_times,
                    publish, record, run, tool_versions, verify_source)


def input_spec():
    inputs = json.loads((HERE.parent / 'packaging/inputs.json').read_text())
    return next(item for item in inputs['packages'] if item['name'] == 'zerotier')


def prepare(context):
    path = obtain_input(input_spec(), context['options'], context['temporary'])
    source = verify_source(path, input_spec())
    root = context['temporary'] / 'root'
    root.mkdir(mode=source['directories']['']['mode'])
    root.chmod(source['directories']['']['mode'])
    run(['apk', 'extract', '--allow-untrusted', '--destination', root, path])
    preserve_link_times(root, source['files'])
    expected = stage_files(root, source)
    return {'input': path, 'source': source, 'root': root, 'expected': expected}


def package(context, prepared):
    run(['apk', 'version', '--check', VERSION])
    require(run(['apk', 'version', '--test', VERSION, '1.16.0_p1-r1']) == '>',
            'Backend update must be newer than installed p1')
    output = context['staging'] / f'zerotier-{VERSION}-aarch64_generic.apk'
    command = ['apk', 'mkpkg', '--compat', '3.0.0_pre1', '--compression', 'deflate:0',
               '--files', prepared['root'], '--output', output, '--sign-key', context['private']]
    command += package_arguments(expected_info(prepared['source']['info']),
                                 prepared['expected']['scripts'], context['temporary'])
    run(command)
    candidate = read_package(output)
    audit_package(prepared['source'], candidate, prepared['expected'])
    run(['apk', '--keys-dir', context['keys'], '--repositories-file', '/dev/null',
         '--no-network', 'verify', output])
    return candidate, output


def manifest(context, prepared, result):
    candidate, output = result
    changed = [name for name in sorted(candidate['files'])
               if candidate['files'][name] != prepared['source']['files'].get(name)]
    return {'status': 'PASS', 'input': dict(record(prepared['input']), url=input_spec()['url']),
            'provenance': input_spec(),
            'package': {'output': record(output), 'info': candidate['info'],
                        'files': candidate['files'], 'directories': candidate['directories'],
                        'scripts': {key: {'sha256': hashlib.sha256(value).hexdigest(),
                                         'size': len(value)}
                                    for key, value in candidate['scripts'].items()}},
            'reviewed_payload_changes': changed,
            'reviewed_lifecycle_changes': ['post-install', 'post-upgrade'],
            'core_binary_preserved': True, 'signature_verified': True,
            'tool_versions': context['versions'], 'kernel_evidence': context['kernel'],
            'sources': [dict(record(p), path=p.relative_to(HERE).as_posix())
                        for p in sorted(HERE.rglob('*')) if p.is_file()],
            'private_key_exported': False, 'target_device_modified': False,
            'installation_and_runtime_verified': False}


def build(options):
    require(not options.output.exists() or not any(options.output.iterdir()), 'Output must be empty')
    kernel = verify_kernel_evidence(json.loads(options.kernel_validation.read_text()),
                                    options.kernel_config.read_bytes())
    versions = tool_versions()
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='f50-backend-key-', dir='/dev/shm') as key_directory:
        with tempfile.TemporaryDirectory(prefix='f50-backend-') as workspace:
            temporary = Path(workspace)
            staging = temporary / 'publish'
            keys = staging / 'keys'
            keys.mkdir(parents=True)
            context = {'options': options, 'temporary': temporary, 'staging': staging,
                       'keys': keys, 'private': create_key(Path(key_directory), keys),
                       'versions': versions, 'kernel': kernel}
            prepared = prepare(context)
            report = manifest(context, prepared, package(context, prepared))
            publish(staging, options.output, report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-dir', type=Path)
    parser.add_argument('--kernel-validation', type=Path, required=True)
    parser.add_argument('--kernel-config', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    report = build(parser.parse_args())
    print(json.dumps({'status': report['status'], 'package': report['package']['output']}, indent=2))


if __name__ == '__main__':
    main()
