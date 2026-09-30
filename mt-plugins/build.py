"""Repackage only nlbwmon/Tailscale metadata; never install or execute their payloads."""
import argparse
import json
import os
from pathlib import Path
import tempfile

from policy import audit_package, expected_info, verify_kernel
from apk3 import read_package, require
from repack import (create_key, obtain_input, package_arguments, preserve_link_times,
                    publish, record, run, tool_versions, verify_source)

HERE = Path(__file__).resolve().parent


def adapt(spec, context):
    temporary = context['temporary']
    source_path = obtain_input(spec, context['options'], temporary)
    source = verify_source(source_path, spec)
    run(['apk', 'version', '--check', spec['version']])
    require(run(['apk', 'version', '--test', spec['version'], spec['source_version']]) == '>',
            'Adapted version must compare newer than upstream')
    workspace = temporary / spec['name']
    root = workspace / 'root'
    root.mkdir(parents=True)
    root.chmod(source['directories']['']['mode'])
    run(['apk', 'extract', '--allow-untrusted', '--destination', root, source_path])
    preserve_link_times(root, source['files'])
    expected = expected_info(source['info'], spec)
    output = context['staging'] / f"{spec['name']}-{spec['version']}-{spec['arch']}.apk"
    command = ['apk', 'mkpkg', '--compat', '3.0.0_pre1', '--compression', 'deflate:0',
               '--files', root, '--output', output, '--sign-key', context['private']]
    run(command + package_arguments(expected, source['scripts'], workspace))
    candidate = read_package(output)
    audit = audit_package(source, candidate, spec)
    run(['apk', '--keys-dir', context['keys'], '--repositories-file', '/dev/null',
         '--no-network', 'verify', output])
    return {'input': dict(record(source_path), url=spec['url']), 'output': record(output),
            'source_info': source['info'], 'adapted_info': candidate['info'], 'audit': audit,
            'signature_verified': True, 'upstream_startup_behavior_preserved': True}


def build(options):
    require(not options.output.exists() or not any(options.output.iterdir()),
            'Output directory must be empty')
    settings = json.loads((HERE / 'inputs.json').read_text())
    versions = tool_versions()
    report = json.loads(options.kernel_validation.read_text())
    kernel = verify_kernel(report, options.kernel_config.read_bytes())
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='f50-mt-key-', dir='/dev/shm') as private_name:
        with tempfile.TemporaryDirectory(prefix='f50-mt-pack-') as temporary_name:
            temporary = Path(temporary_name)
            staging = temporary / 'publish'
            keys = staging / 'keys'
            keys.mkdir(parents=True)
            private = create_key(Path(private_name), keys)
            context = {'temporary': temporary, 'staging': staging, 'keys': keys,
                       'private': private, 'options': options}
            packages = [adapt(spec, context) for spec in settings['packages']]
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
    parser.add_argument('--input-dir', type=Path, help='Optional exact upstream APK cache')
    parser.add_argument('--kernel-validation', type=Path, required=True)
    parser.add_argument('--kernel-config', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    manifest = build(parser.parse_args())
    print(json.dumps({'status': manifest['status'], 'packages':
                      [item['output'] for item in manifest['packages']]}, indent=2))


if __name__ == '__main__':
    main()
