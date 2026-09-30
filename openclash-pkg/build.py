"""Build fixed-source OpenClash and official Mihomo APKs on native ARM64 Alpine."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile

from model import HERE, audit_package, package_specs, require, verify_kernel
from apk3 import read_package
from repack import create_key, package_arguments, publish, record, run, tool_versions
from prepare import prepare_inputs
from stage import lifecycle_scripts, stage_package


def build_package(spec, context):
    name, info = spec['info']['name'], spec['info']
    workspace = context['temporary'] / name
    expected = stage_package(spec, {'root': workspace / 'root', 'materials': context['materials']})
    expected['scripts'] = lifecycle_scripts(spec, context['materials']['source'])
    output = context['staging'] / f"{name}-{info['version']}-{info['arch']}.apk"
    run(['apk', 'version', '--check', info['version']])
    command = ['apk', 'mkpkg', '--compat', '3.0.0_pre1', '--compression', 'deflate:0',
               '--files', workspace / 'root', '--output', output, '--sign-key', context['private']]
    command += package_arguments(info, expected['scripts'], workspace)
    run(command)
    candidate = read_package(output)
    audit_package(candidate, expected, info)
    run(['apk', '--keys-dir', context['keys'], '--repositories-file', '/dev/null',
         '--no-network', 'verify', output])
    scripts = {kind: {'sha256': hashlib.sha256(body).hexdigest(), 'size': len(body),
                       'text': body.decode()} for kind, body in candidate['scripts'].items()}
    return {'output': record(output), 'info': candidate['info'],
            'files': candidate['files'], 'directories': candidate['directories'],
            'scripts': scripts, 'signature_verified': True}


def assemble(context):
    materials = prepare_inputs(context)
    staging = context['temporary'] / 'publish'
    keys = staging / 'keys'
    keys.mkdir(parents=True)
    private = create_key(context['private_directory'], keys)
    package_context = dict(context, materials=materials, staging=staging, keys=keys, private=private)
    packages = [build_package(spec, package_context) for spec in package_specs()]
    sources = staging / 'sources'
    sources.mkdir()
    for archive in materials['archives'].values():
        shutil.copyfile(archive, sources / archive.name)
    shutil.copyfile(HERE / 'SOURCE-NOTICE.txt', sources / 'SOURCE-NOTICE.txt')
    return staging, {'status': 'PASS', 'packages': packages, 'inputs': materials['report'],
                     'public_key': record(keys / 'f50-packaging.pem'),
                     'private_key_exported': False, 'device_modified': False,
                     'proxy_enabled_or_traffic_verified': False}


def build(options):
    require(not options.output.exists() or not any(options.output.iterdir()), 'Output must be empty')
    kernel = verify_kernel(options.kernel_config.read_bytes(), json.loads(options.kernel_validation.read_text()))
    versions = tool_versions()
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='f50-openclash-key-', dir='/dev/shm') as key_directory:
        with tempfile.TemporaryDirectory(prefix='f50-openclash-') as directory:
            context = {'temporary': Path(directory), 'private_directory': Path(key_directory),
                       'input_dir': options.input_dir}
            staging, manifest = assemble(context)
            manifest.update(kernel_evidence=kernel, tool_versions=versions,
                            source_lock=json.loads((HERE / 'source-lock.json').read_text()),
                            packaging_sources=[dict(record(p), path=p.relative_to(HERE).as_posix())
                                               for p in sorted(HERE.rglob('*')) if p.is_file()])
            publish(staging, options.output, manifest)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--kernel-config', type=Path, required=True)
    parser.add_argument('--kernel-validation', type=Path, required=True)
    parser.add_argument('--input-dir', type=Path)
    options = parser.parse_args()
    result = build(options)
    print(json.dumps({'status': result['status'], 'packages': [p['output'] for p in result['packages']]}))


if __name__ == '__main__':
    main()
