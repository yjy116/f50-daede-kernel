"""Repack pinned official Tailscale LuCI APKs with a persistent VPN menu."""
import argparse
import difflib
import json
import os
from pathlib import Path
import tempfile

from policy import MENU_PATH, UI_NAME, audit_package, audit_routes, expected_info, patch_menu
from apk3 import read_package, require
from repack import (create_key, obtain_input, package_arguments, preserve_link_times,
                    publish, record, run, tool_versions)

HERE = Path(__file__).resolve().parent


def verify_source(path, spec):
    require(path.stat().st_size == spec['size'], 'Input size mismatch')
    source = read_package(path)
    require(source['signature_blocks'] == 0, 'Unexpected source signature count')
    for field, value in (('name', spec['name']), ('version', spec['source_version']),
                         ('arch', spec['arch'])):
        require(source['info'][field] == value, f'Unexpected source {field}')
    return source


def modify_menu(root, source, staging):
    path = root / MENU_PATH
    original = path.read_bytes()
    patched = patch_menu(original)
    path.write_bytes(patched)
    timestamp = source['files'][MENU_PATH]['mtime']
    os.utime(path, (timestamp, timestamp))
    difference = ''.join(difflib.unified_diff(original.decode().splitlines(True),
                                            patched.decode().splitlines(True),
                                            fromfile='upstream/' + MENU_PATH,
                                            tofile='f50/' + MENU_PATH))
    (staging / 'tailscale-menu.diff').write_text(difference, encoding='utf-8')
    return {'original_menu': original, 'route_audit': audit_routes(root)}


def adapt(spec, context):
    source_path = obtain_input(spec, context['options'], context['temporary'])
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
    if spec['name'] == UI_NAME:
        options.update(modify_menu(root, source, context['staging']))
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
            'signature_verified': True, 'route_audit': options.get('route_audit')}


def build(options):
    require(not options.output.exists() or not any(options.output.iterdir()), 'Output must be empty')
    settings = json.loads((HERE / 'inputs.json').read_text())
    versions = tool_versions()
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='f50-vpn-key-', dir='/dev/shm') as private_name:
        with tempfile.TemporaryDirectory(prefix='f50-vpn-') as temporary_name:
            temporary = Path(temporary_name)
            staging = temporary / 'publish'
            keys = staging / 'keys'
            keys.mkdir(parents=True)
            private = create_key(Path(private_name), keys)
            context = {'temporary': temporary, 'staging': staging, 'keys': keys,
                       'private': private, 'options': options}
            packages = [adapt(spec, context) for spec in settings['packages']]
            manifest = {'status': 'PASS', 'provenance': settings, 'packages': packages,
                        'tool_versions': versions, 'public_key': record(keys / 'f50-packaging.pem'),
                        'packaging_sources': [record(p) for p in sorted(HERE.iterdir()) if p.is_file()],
                        'private_key_exported': False, 'backend_repacked': False,
                        'source_authentication': 'Pinned SHA256 from previously verified official signed index',
                        'device_runtime_tested_by_packager': False}
            publish(staging, options.output, manifest)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-dir', type=Path, help='Optional cache of the two exact official APKs')
    parser.add_argument('--output', type=Path, required=True)
    manifest = build(parser.parse_args())
    print(json.dumps({'status': manifest['status'], 'packages':
                      [p['output'] for p in manifest['packages']]}, indent=2))


if __name__ == '__main__':
    main()
