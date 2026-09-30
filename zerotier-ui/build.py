#!/usr/bin/env python3
"""Build and audit an APK without installing or starting ZeroTier."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

from package_model import (HERE, PACKAGE_NAME, PACKAGE_VERSION, audit_package,
                           lifecycle_scripts, package_info, stage_files)

sys.path.insert(0, str(HERE.parent / 'packaging'))
from apk3 import read_package, require
from repack import create_key, package_arguments, publish, record, run, tool_versions


def build_package(context):
    root = context['temporary'] / 'root'
    expected = dict(stage_files(root), scripts=lifecycle_scripts())
    output = context['staging'] / f'{PACKAGE_NAME}-{PACKAGE_VERSION}-noarch.apk'
    run(['apk', 'version', '--check', PACKAGE_VERSION])
    command = ['apk', 'mkpkg', '--compat', '3.0.0_pre1', '--compression', 'deflate:0',
               '--files', root, '--output', output, '--sign-key', context['private']]
    command += package_arguments(package_info(), expected['scripts'], context['temporary'])
    run(command)
    candidate = read_package(output)
    audit_package(candidate, expected)
    run(['apk', '--keys-dir', context['keys'], '--repositories-file', '/dev/null',
         '--no-network', 'verify', output])
    return {'output': record(output), 'info': candidate['info'],
            'files': candidate['files'], 'directories': candidate['directories'],
            'scripts': {key: {'sha256': hashlib.sha256(value).hexdigest(), 'size': len(value)}
                        for key, value in candidate['scripts'].items()},
            'signature_verified': True}


def build(output):
    require(not output.exists() or not any(output.iterdir()), 'Output directory must be empty')
    versions = tool_versions()
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='f50-ui-key-', dir='/dev/shm') as private_dir:
        with tempfile.TemporaryDirectory(prefix='f50-ui-') as temporary_dir:
            temporary = Path(temporary_dir)
            staging = temporary / 'publish'
            keys = staging / 'keys'
            keys.mkdir(parents=True)
            private = create_key(Path(private_dir), keys)
            package = build_package({'temporary': temporary, 'staging': staging,
                                     'keys': keys, 'private': private})
            manifest = {'status': 'PASS', 'package': package, 'tool_versions': versions,
                        'provenance': json.loads((HERE / 'provenance.json').read_text()),
                        'sources': [dict(record(p), path=p.relative_to(HERE).as_posix())
                                    for p in sorted(HERE.rglob('*')) if p.is_file()],
                        'public_key': record(keys / 'f50-packaging.pem'),
                        'private_key_exported': False, 'device_modified': False,
                        'installation_and_browser_verified': False}
            publish(staging, output, manifest)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    options = parser.parse_args()
    manifest = build(options.output)
    print(json.dumps({'status': manifest['status'], 'package': manifest['package']['output']}, indent=2))


if __name__ == '__main__':
    main()
