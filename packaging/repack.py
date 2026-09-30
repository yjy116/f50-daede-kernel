#!/usr/bin/env python3
"""Repack hash-pinned upstream APKs; run as root in the pinned Alpine container."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import urllib.request

from apk3 import DEPENDENCY_FIELDS, read_package, require
from package_audit import (audit_repack, expected_info, verify_default_disabled,
                           verify_kernel_evidence)

HERE = Path(__file__).resolve().parent
TIMEOUT_SECONDS = 60
HASH_CHUNK_BYTES = 1024 * 1024
DERIVED_FIELDS = {'hashes', 'installed-size', 'file-size'}


def run(arguments):
    env = dict(os.environ, LC_ALL='C', LANG='C')
    env.pop('SOURCE_DATE_EPOCH', None)  # apk_get_build_time would replace every original mtime.
    result = subprocess.run([str(arg) for arg in arguments], capture_output=True,
                            text=True, env=env, timeout=TIMEOUT_SECONDS, check=False)
    require(result.returncode == 0, f'{arguments[0]} failed ({result.returncode}): '
            f'{result.stdout}\n{result.stderr}')
    require('WARNING' not in result.stderr.upper(),
            f'{arguments[0]} reported a warning: {result.stderr}')
    return result.stdout.strip()


def record(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(HASH_CHUNK_BYTES), b''):
            digest.update(block)
    return {'name': path.name, 'size': path.stat().st_size, 'sha256': digest.hexdigest()}


def obtain_input(spec, options, temporary):
    name = spec['url'].rsplit('/', 1)[1]
    destination = temporary / name
    if options.input_dir:
        shutil.copyfile(options.input_dir / name, destination)
    else:
        request = urllib.request.Request(spec['url'], headers={'User-Agent': 'F50-APK-Audit/1'})
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as source:
            with destination.open('wb') as target:
                shutil.copyfileobj(source, target, HASH_CHUNK_BYTES)
    require(record(destination)['sha256'] == spec['sha256'], f'Input SHA256 mismatch: {name}')
    return destination


def verify_source(path, spec):
    package = read_package(path)
    for field, expected in (('name', spec['name']), ('version', spec['source_version']),
                            ('arch', spec['arch'])):
        require(package['info'][field] == expected, f'Source {field} mismatch')
    require(package['signature_blocks'] == 0, 'Reviewed source was an unsigned APK')
    if 'binary_sha256' in spec:
        require(package['files'][spec['binary_path']]['sha256'] == spec['binary_sha256'],
                'Upstream binary hash mismatch')
    links = {name: member['target'] for name, member in package['files'].items()
             if member['type'] == 'symlink'}
    require(links == spec.get('symlinks', {}), 'Unexpected symlink manifest')
    if spec['name'] == 'daed':
        verify_default_disabled(package)
    return package


def package_arguments(info, scripts, directory):
    arguments = []
    for key, value in info.items():
        if key in DERIVED_FIELDS:
            continue
        if key in DEPENDENCY_FIELDS:
            value = ' '.join(value)
        arguments.extend(['--info', f'{key}:{value}'])
    script_directory = directory / 'scripts'
    script_directory.mkdir()
    for kind, body in scripts.items():
        path = script_directory / kind
        path.write_bytes(body)
        arguments.extend(['--script', f'{kind}:{path}'])
    return arguments


def adapt_package(spec, context):
    temporary, options, policy = context['temporary'], context['options'], context['policy']
    source_path = obtain_input(spec, options, temporary)
    source = verify_source(source_path, spec)
    run(['apk', 'version', '--check', spec['version']])
    comparison = run(['apk', 'version', '--test', spec['version'], spec['source_version']])
    require(comparison == '>', 'Adapted package version must compare newer than upstream')
    workspace = temporary / spec['name']
    workspace.mkdir()
    root = workspace / 'root'
    root.mkdir()
    # extract treats an existing root directory as EEXIST and does not restore its ACL.
    root.chmod(source['directories']['']['mode'])
    # Only host/cloud input extraction, after exact SHA256 check; never an install bypass.
    run(['apk', 'extract', '--allow-untrusted', '--destination', root, source_path])
    expected = expected_info(source['info'], policy)
    output = context['staging'] / f"{spec['name']}-{spec['version']}-{spec['arch']}.apk"
    command = ['apk', 'mkpkg', '--compat', '3.0.0_pre1', '--compression', 'deflate:0',
               '--files', root, '--output', output, '--sign-key', context['private_key']]
    command += package_arguments(expected, source['scripts'], workspace)
    run(command)
    candidate = read_package(output)
    audit = audit_repack(source, candidate, policy)
    run(['apk', '--keys-dir', context['keys'], '--repositories-file', '/dev/null',
         '--no-network', 'verify', output])
    return {'input': dict(record(source_path), url=spec['url']), 'output': record(output),
            'source_info': source['info'], 'adapted_info': candidate['info'],
            'audit': audit, 'signature_verified': True,
            'default_config': verify_default_disabled(candidate) if spec['name'] == 'daed' else None}


def create_key(private_directory, keys):
    private = private_directory / 'signing-private.pem'
    run(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt',
         'ec_paramgen_curve:prime256v1', '-out', private])
    require(private.stat().st_mode & 0o077 == 0, 'Private key permissions are not private')
    public = keys / 'f50-packaging.pem'
    run(['openssl', 'pkey', '-in', private, '-pubout', '-out', public])
    require(b'PRIVATE KEY' not in public.read_bytes(), 'Refusing to export a private key')
    return private


def tool_versions():
    require(os.geteuid() == 0, 'Root container is required to preserve ownership')
    version = run(['apk', '--version'])
    require('apk-tools 3.0.8,' in version, f'Unexpected apk-tools version: {version}')
    return {'apk': version, 'openssl': run(['openssl', 'version']), 'python': sys.version,
            'installed_packages': run(['apk', 'info', '-v'])}


def package_all(context, settings):
    packages = []
    daed_version = next(item['version'] for item in settings['packages'] if item['name'] == 'daed')
    for spec in settings['packages']:
        policy = dict(spec, description_suffix=settings['description_suffix'], daed_version=daed_version)
        packages.append(adapt_package(spec, dict(context, policy=policy)))
    return packages


def publish(staging, output, manifest):
    manifest_path = staging / 'packaging-manifest.json'
    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    checksums = [f"{record(path)['sha256']}  {path.relative_to(staging).as_posix()}"
                 for path in sorted(staging.rglob('*')) if path.is_file()]
    (staging / 'SHA256SUMS').write_text('\n'.join(checksums) + '\n', encoding='ascii')
    output.mkdir(parents=True, exist_ok=True)
    output.chmod(0o755)
    for path in staging.rglob('*'):
        destination = output / path.relative_to(staging)
        if path.is_dir():
            destination.mkdir(exist_ok=True)
            destination.chmod(0o755)
        else:
            shutil.copyfile(path, destination)
            destination.chmod(0o644)


def build(options):
    require(not options.output.exists() or not any(options.output.iterdir()),
            'Output directory must be empty to prevent mixing signing rounds')
    settings = json.loads((HERE / 'inputs.json').read_text())
    versions = tool_versions()
    evidence = json.loads(options.kernel_validation.read_text())
    kernel = verify_kernel_evidence(evidence, options.kernel_config.read_bytes())
    os.umask(0o077)
    # tmpfs is outside /out; no Docker layer, log or artifact receives the private key.
    with tempfile.TemporaryDirectory(prefix='f50-key-', dir='/dev/shm') as private_name:
        with tempfile.TemporaryDirectory(prefix='f50-pack-') as temporary_name:
            temporary = Path(temporary_name)
            staging = temporary / 'publish'
            keys = staging / 'keys'
            keys.mkdir(parents=True)
            private = create_key(Path(private_name), keys)
            context = {'temporary': temporary, 'options': options, 'staging': staging,
                       'keys': keys, 'private_key': private}
            packages = package_all(context, settings)
            manifest = {'status': 'PASS', 'provenance': settings, 'packages': packages,
                        'kernel_evidence': dict(kernel, file=record(options.kernel_validation)),
                        'tool_versions': versions, 'public_key': record(keys / 'f50-packaging.pem'),
                        'packaging_sources': [record(p) for p in sorted(HERE.iterdir()) if p.is_file()],
                        'private_key_exported': False, 'target_device_modified': False,
                        'install_or_daemon_runtime_verified': False}
            publish(staging, options.output, manifest)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-dir', type=Path, help='Optional cache of exact upstream APKs')
    parser.add_argument('--kernel-validation', type=Path, required=True)
    parser.add_argument('--kernel-config', type=Path, required=True,
                        help='Exact kernel.config bound by the validation report .config SHA256')
    parser.add_argument('--output', type=Path, required=True)
    options = parser.parse_args()
    manifest = build(options)
    print(json.dumps({'status': manifest['status'], 'output': str(options.output),
                      'packages': [item['output'] for item in manifest['packages']]}, indent=2))


if __name__ == '__main__':
    main()
