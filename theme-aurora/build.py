"""Add a temporary-key signature to the fixed upstream APK; never execute it."""
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

from audit import audit_models, json_record, unsigned_blocks
from apk3 import read_package, require

TOOL_TIMEOUT_SECONDS = 60
PUBLIC_KEY_NAME = 'f50-aurora.pem'


def run(command):
    result = subprocess.run([str(arg) for arg in command], check=True,
                            capture_output=True, text=True, timeout=TOOL_TIMEOUT_SECONDS)
    return result.stdout.strip()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fetch_pinned(spec, destination):
    require(spec['url'].startswith('https://github.com/eamonxg/luci-theme-aurora/'),
            'Unexpected input origin')
    request = urllib.request.Request(spec['url'], headers={'User-Agent': 'F50-Aurora-audit'})
    with urllib.request.urlopen(request, timeout=TOOL_TIMEOUT_SECONDS) as response:
        require(response.url.startswith('https://'), 'Non-HTTPS download redirect')
        destination.write_bytes(response.read())
    require(destination.stat().st_size == spec['size'], 'Pinned input size mismatch')
    require(digest(destination) == spec['sha256'], 'Pinned input SHA256 mismatch')


def key_pair(directory):
    private = directory / 'private.pem'
    keys = directory / 'keys'
    keys.mkdir()
    public = keys / PUBLIC_KEY_NAME
    run(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt',
         'ec_paramgen_curve:prime256v1', '-out', private])
    require(private.stat().st_mode & 0o077 == 0, 'Private key mode is not private')
    run(['openssl', 'pkey', '-in', private, '-pubout', '-out', public])
    require(b'PRIVATE KEY' not in public.read_bytes(), 'Refusing private key export')
    return {'private': private, 'public': public, 'keys': keys}


def versions():
    apk = run(['apk', '--version'])
    require(apk.startswith('apk-tools 3.0.8-r0, compiled for '), 'Unexpected apk-tools version')
    return {'apk': apk, 'openssl': run(['openssl', 'version']), 'python': sys.version,
            'installed_packages': run(['apk', 'info', '-v'])}


def sign_and_audit(source_path, context):
    source = read_package(source_path)
    for name in ('name', 'version', 'arch', 'license'):
        require(source['info'][name] == context['spec'][name], f'Unexpected source {name}')
    require(source['signature_blocks'] == 0, 'Pinned input unexpectedly signed')
    signed_path = source_path.with_name('signed.apk')
    shutil.copyfile(source_path, signed_path)
    run(['apk', 'adbsign', '--allow-untrusted', '--sign-key', context['private'], '--compression',
         'deflate:0', signed_path])
    run(['apk', '--keys-dir', context['keys'], '--repositories-file', '/dev/null',
         '--no-network', 'verify', signed_path])
    signed = read_package(signed_path)
    audit_models(source, signed)
    raw = unsigned_blocks(source_path.read_bytes())
    require(raw == unsigned_blocks(signed_path.read_bytes()), 'Non-signature ADB bytes changed')
    report = {'source': json_record(source), 'signed': json_record(signed),
              'non_signature_adb_sha256': hashlib.sha256(raw).hexdigest(),
              'non_signature_bytes_exact': True, 'signature_verified': True}
    return signed_path, report


def publish(context, result):
    signed_path, audit = result
    output = context['output']
    require(not output.exists() or not any(output.iterdir()), 'Output directory must be empty')
    output.mkdir(parents=True, exist_ok=True)
    package = output / context['spec']['filename']
    public = output / PUBLIC_KEY_NAME
    shutil.copyfile(signed_path, package)
    shutil.copyfile(context['public'], public)
    manifest = dict(input=context['spec'], audit=audit, tools=context['tools'],
                    public_key_sha256=digest(public),
                    trust='One build-local key; verify via an isolated temporary keys directory',
                    scripts_executed=False)
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    artifacts = sorted(output.iterdir())
    (output / 'SHA256SUMS').write_text(''.join(f'{digest(p)}  {p.name}\n' for p in artifacts),
                                      encoding='utf-8')
    for path in output.iterdir():
        path.chmod(0o644)
    output.chmod(0o755)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    spec = json.loads(Path(__file__).with_name('input.json').read_text(encoding='utf-8'))
    tool_versions = versions()
    with tempfile.TemporaryDirectory(prefix='f50-aurora-', dir='/dev/shm') as temporary:
        directory = Path(temporary)
        source = directory / spec['filename']
        fetch_pinned(spec, source)
        context = dict(key_pair(directory), spec=spec, output=args.output, tools=tool_versions)
        publish(context, sign_and_audit(source, context))
    print('PASS: signature verified; original metadata, files, directories and scripts unchanged')


if __name__ == '__main__':
    main()
