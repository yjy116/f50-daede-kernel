"""Build fixed HomeProxy packages and its compatible official sing-box core."""
import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile

from model import HERE, audit_package, package_specs, require, verify_kernel
from apk3 import read_package
from repack import create_key, package_arguments, publish, record, run, tool_versions
from checks import check_capability_helper, check_generated
from patch_features import patch_ui
from prepare import compile_translation, prepare
from stage import stage_core, stage_ui


def pack(info, expected, context):
    output = context['staging'] / f"{info['name']}-{info['version']}-{info['arch']}.apk"
    run(['apk', 'version', '--check', info['version']])
    command = ['apk', 'mkpkg', '--compat', '3.0.0_pre1', '--compression', 'deflate:0',
               '--files', context['root'], '--output', output, '--sign-key', context['private']]
    run(command + package_arguments(info, expected['scripts'], context['root'].parent))
    candidate = read_package(output)
    audit_package(candidate, expected, info)
    run(['apk', '--keys-dir', context['keys'], '--repositories-file', '/dev/null', '--no-network', 'verify', output])
    return {'output': record(output), 'info': candidate['info'], 'signature_verified': True,
            'files': candidate['files'], 'directories': candidate['directories'],
            'scripts': {k: {'size': len(v), 'sha256': hashlib.sha256(v).hexdigest(), 'text': v.decode()}
                        for k, v in candidate['scripts'].items()}}


def record_patches(materials, staging):
    source = materials['source']
    originals = {p.relative_to(source).as_posix(): p.read_bytes() for p in source.rglob('*') if p.is_file()}
    changed = patch_ui(source)
    actual = [name for name, content in originals.items() if (source / name).read_bytes() != content]
    require(set(changed) == set(actual), 'Unexpected patched file set')
    lines = []
    for name in changed:
        lines.extend(difflib.unified_diff(originals[name].decode().splitlines(True),
                                          (source / name).read_text().splitlines(True),
                                          fromfile='upstream/' + name, tofile='f50/' + name))
    (staging / 'homeproxy.diff').write_text(''.join(lines))
    return changed


def assemble(context):
    materials = prepare(context)
    context = dict(context, materials=materials)
    changed = record_patches(materials, context['staging'])
    run(['node', '--check', materials['source'] / 'htdocs/luci-static/resources/view/homeproxy/client.js'])
    run(['ucode', '-c', '-o', context['temporary'] / 'rpc.bc',
         materials['source'] / 'root/usr/share/rpcd/ucode/luci.homeproxy'])
    check_capability_helper(context['temporary'])
    checks = check_generated(materials, context['staging'])
    materials['translation'] = compile_translation(materials, context['temporary'])
    packages = []
    core_context = dict(context, root=context['temporary'] / 'sing-box/root')
    info, expected = stage_core(core_context)
    packages.append(pack(info, expected, core_context))
    for spec in package_specs():
        staging = dict(context, root=context['temporary'] / spec['info']['name'] / 'root')
        packages.append(pack(spec['info'], stage_ui(spec, staging), staging))
    sources = context['staging'] / 'sources'
    sources.mkdir()
    for archive in materials['archives'].values():
        shutil.copyfile(archive, sources / archive.name)
    return {'packages': packages, 'inputs': materials['inputs'], 'core_evidence': materials['core_evidence'],
            'configuration_checks': checks, 'patched_ui_files': changed,
            'core_payload_changes': ['usr/bin/sing-box'], 'daemon_started': False}


def build(options):
    require(not options.output.exists() or not any(options.output.iterdir()), 'Output must be empty')
    kernel = verify_kernel(options.kernel_config.read_bytes(), json.loads(options.kernel_validation.read_text()))
    versions = tool_versions()
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='f50-hp-key-', dir='/dev/shm') as key_dir:
        with tempfile.TemporaryDirectory(prefix='f50-hp-') as directory:
            temporary = Path(directory)
            staging = temporary / 'publish'
            keys = staging / 'keys'
            keys.mkdir(parents=True)
            private = create_key(Path(key_dir), keys)
            context = {'options': options, 'temporary': temporary, 'staging': staging,
                       'keys': keys, 'private': private}
            manifest = assemble(context)
            manifest.update(status='PASS', kernel_evidence=kernel, tool_versions=versions,
                            public_key=record(keys / 'f50-packaging.pem'), private_key_exported=False,
                            packaging_sources=[dict(record(p), path=p.relative_to(HERE).as_posix())
                                               for p in sorted(HERE.rglob('*')) if p.is_file()])
            publish(staging, options.output, manifest)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel-validation', type=Path, required=True)
    parser.add_argument('--kernel-config', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--input-dir', type=Path)
    result = build(parser.parse_args())
    print(json.dumps({'status': result['status'], 'packages': [p['output'] for p in result['packages']]}))


if __name__ == '__main__':
    main()
