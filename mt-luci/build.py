"""Build seven reviewed APKs together; never install packages on the device."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile

from mt_model import HERE, audit_package, lifecycle_scripts, package_specs, require
from apk3 import read_package
from repack import create_key, package_arguments, publish, record, run, tool_versions
from compile_tools import compile_inputs
from stage import stage_package


def verify_sources():
    lock = json.loads((HERE / 'source-lock.json').read_text())
    actual = {p.relative_to(HERE).as_posix(): record(p)['sha256']
              for p in sorted((HERE / 'vendor').rglob('*')) if p.is_file()}
    require(actual == lock['files'], 'Vendored payload differs from the reviewed source lock')
    return lock


def build_package(spec, context):
    name = spec['info']['name']
    workspace = context['temporary'] / name
    root = workspace / 'root'
    expected = stage_package(spec, {'root': root, 'tools': context['tools']})
    expected['scripts'] = lifecycle_scripts(name)
    info = spec['info']
    output = context['staging'] / f"{name}-{info['version']}-{info['arch']}.apk"
    run(['apk', 'version', '--check', info['version']])
    command = ['apk', 'mkpkg', '--compat', '3.0.0_pre1', '--compression', 'deflate:0',
               '--files', root, '--output', output, '--sign-key', context['private']]
    command += package_arguments(info, expected['scripts'], workspace)
    run(command)
    candidate = read_package(output)
    audit_package(candidate, expected, info)
    run(['apk', '--keys-dir', context['keys'], '--repositories-file', '/dev/null',
         '--no-network', 'verify', output])
    scripts = {key: {'sha256': hashlib.sha256(value).hexdigest(), 'size': len(value)}
               for key, value in candidate['scripts'].items()}
    return {'output': record(output), 'info': candidate['info'],
            'files': candidate['files'], 'directories': candidate['directories'],
            'scripts': scripts, 'signature_verified': True}


def package_all(temporary, private_dir):
    staging = temporary / 'publish'
    keys = staging / 'keys'
    keys.mkdir(parents=True)
    private = create_key(private_dir, keys)
    tools = compile_inputs(temporary)
    context = dict(temporary=temporary, staging=staging, keys=keys, private=private, tools=tools)
    packages = [build_package(spec, context) for spec in package_specs()]
    shutil.copytree(tools['logs'], staging / 'logs')
    manifest = {'status': 'PASS', 'packages': packages, 'core': tools['report'],
                'public_key': record(keys / 'f50-packaging.pem'),
                'private_key_exported': False, 'device_modified': False,
                'installation_and_browser_verified': False}
    return staging, manifest


def build(output):
    require(not output.exists() or not any(output.iterdir()), 'Output directory must be empty')
    lock = verify_sources()
    versions = tool_versions()
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='f50-mt-key-', dir='/dev/shm') as key_dir:
        with tempfile.TemporaryDirectory(prefix='f50-mt-') as workspace:
            staging, manifest = package_all(Path(workspace), Path(key_dir))
            manifest.update(tool_versions=versions, source_lock=lock,
                            provenance=json.loads((HERE / 'provenance.json').read_text()),
                            sources=[dict(record(p), path=p.relative_to(HERE).as_posix())
                                     for p in sorted(HERE.rglob('*')) if p.is_file()])
            publish(staging, output, manifest)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    options = parser.parse_args()
    manifest = build(options.output)
    print(json.dumps({'status': manifest['status'],
                      'packages': [p['output'] for p in manifest['packages']]}, indent=2))


if __name__ == '__main__':
    main()
