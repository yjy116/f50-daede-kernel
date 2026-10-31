"""Finalize a fresh private 7.2.13 capture; never connects to the device.

After uploading finalized files, collect actual device SHA256 values for every
SHA256SUMS entry plus SHA256SUMS itself. Pass that relative-name manifest with
--verify-only --peer-sha256 FILE to verify the synchronized copy.
"""
import argparse
import copy
import hashlib
import importlib.util
import io
import json
import shutil
import tarfile
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_ssh_public_key

BASE = Path(__file__).resolve().parent
LEGACY = BASE
KERNEL_VERSION = '7.2.13'
KERNEL_NAME = 'mu300-kernel-7.2.tar.gz'
KERNEL_SHA = 'f52f3e043ea5fc6cb58e187a7643a35053b5eda1ad7b5c9de71ae8feae9ff03a'
BUNDLE_DEVICE_PATH = '/mnt/mu300-disk/f50-official-20261031/' + KERNEL_NAME
AUTH_PATH = 'etc/dropbear/authorized_keys'
PROFILE_SHA_PATH = 'etc/mu300/f50-profile/kernel-bundle.sha256'
OUTPUTS = ('settings.tar.gz', 'metadata.json', 'files.sha256', 'links.tsv',
           'restore-metadata.tsv', 'capture-device-archives.sha256',
           'device-archives.sha256', KERNEL_NAME, 'SHA256SUMS')


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


FORMAT = module('f50_finalizer_schema1', LEGACY / 'finalize_snapshot.py')
VERIFY = module('f50_verifier_schema1', LEGACY / 'verify_snapshot.py')
require = VERIFY.require


def public_line(path):
    data = path.read_bytes().rstrip(b'\r\n')
    require(data and b'\n' not in data and b'\r' not in data, 'Expected one SSH public-key line')
    require(b'PRIVATE KEY' not in data, 'A public key is required')
    try:
        load_ssh_public_key(data)
    except (ValueError, TypeError) as error:
        raise VERIFY.SnapshotError('Invalid SSH public key') from error
    return data


def archive_record(member):
    return (member.type, member.mode, member.uid, member.gid, member.mtime,
            member.uname, member.gname, member.linkname, dict(member.pax_headers))


def inventory(path):
    result = {}
    with tarfile.open(path) as archive:
        for member in archive:
            name = VERIFY.relative_path(member.name)
            VERIFY.member_type(member)
            require(name not in result, 'Duplicate archive member')
            sha = None
            if member.isfile():
                sha = hashlib.file_digest(archive.extractfile(member), 'sha256').hexdigest()
            result[name] = (archive_record(member), member.size, sha)
    return result


def archived_file(snapshot, wanted):
    with tarfile.open(snapshot / 'settings.tar.gz') as archive:
        matches = [m for m in archive if VERIFY.relative_path(m.name) == wanted]
        require(len(matches) == 1 and matches[0].isfile(), 'Required capture member missing or not regular')
        return archive.extractfile(matches[0]).read()


def check_release(snapshot, kernel):
    require(VERIFY.local_file(snapshot, 'kernel.txt').read_text().strip() == KERNEL_VERSION,
            'Capture is not the official 7.2.13 running kernel')
    require(VERIFY.file_hash(kernel) == KERNEL_SHA, 'Official kernel bundle SHA mismatch')
    with tarfile.open(kernel) as archive:
        rows = [m for m in archive if m.name.removeprefix('./') == 'kernel.release']
        require(len(rows) == 1 and rows[0].isfile(), 'Kernel release member invalid')
        require(archive.extractfile(rows[0]).read().decode().strip() == KERNEL_VERSION,
                'Official bundle release mismatch')
    profile = archived_file(snapshot, PROFILE_SHA_PATH).decode().splitlines()
    require(len(profile) == 1 and profile[0].split() == [KERNEL_SHA, BUNDLE_DEVICE_PATH],
            'Captured profile does not reference the new verified official bundle')


def check_capture_hashes(snapshot):
    require(not (snapshot / 'INCOMPLETE').exists(), 'Capture is incomplete')
    hashes = VERIFY.sha_manifest(VERIFY.local_file(snapshot, 'device-archives.sha256'))
    require(set(hashes) == set(VERIFY.ARCHIVES), 'Capture archive checksum set differs')
    for name, expected in hashes.items():
        require(VERIFY.file_hash(VERIFY.local_file(snapshot, name)) == expected,
                'Downloaded capture differs from the device archive SHA')


def remove_exact_key(original, stream, key):
    require(original.isfile(), 'authorized_keys must be a regular file')
    lines = stream.read().splitlines(keepends=True)
    removed = sum(line.rstrip(b'\r\n') == key for line in lines)
    data = b''.join(line for line in lines if line.rstrip(b'\r\n') != key)
    member = copy.copy(original)
    member.size = len(data)
    member.pax_headers = {k: v for k, v in original.pax_headers.items() if k != 'size'}
    return member, data, removed


def compare_sanitation(before, after):
    require(before.keys() == after.keys(), 'Sanitation changed archive paths')
    require(all(before[p] == after[p] for p in before if p != AUTH_PATH),
            'Sanitation changed another archive member')
    require(before[AUTH_PATH][0][:8] == after[AUTH_PATH][0][:8], 'Authorization attributes changed')
    old_pax = {k: v for k, v in before[AUTH_PATH][0][8].items() if k != 'size'}
    new_pax = {k: v for k, v in after[AUTH_PATH][0][8].items() if k != 'size'}
    require(old_pax == new_pax, 'Authorization extended attributes changed')


def rewrite_authorizations(context):
    snapshot, key, expected = context
    source, target = snapshot / 'settings.tar.gz', snapshot / 'settings.sanitized.tar.gz'
    before = inventory(source)
    require(AUTH_PATH in before, 'Capture omits authorized_keys')
    removed = 0
    with tarfile.open(source) as old, tarfile.open(target, 'w:gz') as new:
        for original in old:
            member = original
            stream = old.extractfile(original) if original.isfile() else None
            if VERIFY.relative_path(original.name) == AUTH_PATH:
                member, data, removed = remove_exact_key(original, stream, key)
                stream = io.BytesIO(data)
            new.addfile(member, stream)
    require(removed == expected, 'Exact temporary authorization count differs from --expected-key-count')
    compare_sanitation(before, inventory(target))
    target.replace(source)
    require(archived_file(snapshot, AUTH_PATH) == data, 'Other authorization lines changed during rewrite')
    return {'removed_task_keys': removed, 'other_members_verified': len(before) - 1,
            'public_key_line_sha256': hashlib.sha256(key).hexdigest()}


def write_manifests(snapshot, sanitation):
    FORMAT.write_metadata(snapshot, sanitation)
    path = snapshot / 'metadata.json'
    metadata = json.loads(path.read_text(encoding='utf-8'))
    metadata['kernel_bundle'] = {'file': KERNEL_NAME, 'sha256': KERNEL_SHA,
                                 'device_path': BUNDLE_DEVICE_PATH}
    path.write_text(json.dumps(metadata, indent=2) + '\n', encoding='utf-8', newline='\n')
    attributes = ''.join(f"{r['path']}\t{int(r['mode'], 8):o}\t{r['uid']}\t{r['gid']}\n"
                         for r in sorted(metadata['entries'], key=lambda r: r['path']))
    (snapshot / 'restore-metadata.tsv').write_text(attributes, encoding='utf-8', newline='\n')
    shutil.copy2(snapshot / 'device-archives.sha256', snapshot / 'capture-device-archives.sha256')
    hashes = ''.join(f'{VERIFY.file_hash(snapshot / name)}  {name}\n' for name in VERIFY.ARCHIVES)
    (snapshot / 'device-archives.sha256').write_text(hashes, encoding='utf-8', newline='\n')
    files = sorted(p for p in snapshot.iterdir() if p.name != 'SHA256SUMS')
    hashes = ''.join(f'{VERIFY.file_hash(p)}  {p.name}\n' for p in files)
    (snapshot / 'SHA256SUMS').write_text(hashes, encoding='utf-8', newline='\n')


def check_peer(snapshot, manifest):
    actual = VERIFY.sha_manifest(manifest)
    names = set(VERIFY.sha_manifest(snapshot / 'SHA256SUMS')) | {'SHA256SUMS'}
    require(set(actual) == names, 'Peer readback must cover every artifact plus SHA256SUMS itself')
    require(all(VERIFY.file_hash(VERIFY.local_file(snapshot, p)) == sha for p, sha in actual.items()),
            'Device readback SHA differs from the finalized local snapshot')


def validate(snapshot, key, peer=None):
    check_release(snapshot, VERIFY.local_file(snapshot, KERNEL_NAME))
    check_capture_hashes(snapshot)
    require(not any(line.rstrip(b'\r\n') == key for line in archived_file(snapshot, AUTH_PATH).splitlines()),
            'Temporary authorization remains in the snapshot')
    result = VERIFY.verify_snapshot(snapshot, ('lib/modules/' + KERNEL_VERSION, PROFILE_SHA_PATH))
    if peer is not None:
        check_peer(snapshot, peer)
    return {'status': result['status'], 'members': result['members'],
            'sqlite_integrity_check': result['sqlite']['integrity_check'],
            'peer_sha256': 'PASS' if peer is not None else 'NOT_CHECKED'}


def prepare(snapshot, options, key):
    require(not (snapshot / 'metadata.json').exists(), 'Use --verify-only for an already finalized snapshot')
    require(not (snapshot / 'capture-device-archives.sha256').exists(), 'Capture already has finalization provenance')
    require(all(p.is_file() and not p.is_symlink() for p in snapshot.iterdir()),
            'Capture directory must contain only regular artifact files')
    check_capture_hashes(snapshot)
    check_release(snapshot, options.kernel)
    existing = snapshot / KERNEL_NAME
    require(not existing.exists() or VERIFY.file_hash(existing) == KERNEL_SHA, 'Captured kernel bundle differs')
    with tempfile.TemporaryDirectory(prefix='.f50-finalize-', dir=snapshot.parent) as temporary:
        staged = Path(temporary).resolve()
        require(staged.parent == snapshot.parent, 'Staging directory left the intended parent')
        shutil.copytree(snapshot, staged, dirs_exist_ok=True)
        shutil.copy2(options.kernel, staged / KERNEL_NAME)
        sanitation = rewrite_authorizations((staged, key, options.expected_key_count))
        write_manifests(staged, sanitation)
        validate(staged, key)
        (snapshot / 'INCOMPLETE').write_text('Finalization commit in progress\n', encoding='ascii')
        for name in OUTPUTS:
            (staged / name).replace(snapshot / name)
        (snapshot / 'INCOMPLETE').unlink()
    return sanitation


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', type=Path)
    parser.add_argument('--public-key', type=Path, required=True)
    parser.add_argument('--kernel', type=Path, default=BASE / 'official' / KERNEL_NAME)
    parser.add_argument('--expected-key-count', type=int, default=1,
                        help='Exact matching lines expected before removal; use 0 for capture after revocation')
    parser.add_argument('--verify-only', action='store_true')
    parser.add_argument('--peer-sha256', type=Path, help='Actual device readback hashes, with relative filenames')
    args = parser.parse_args()
    try:
        require(args.expected_key_count >= 0, 'Expected key count must be nonnegative')
        require(args.peer_sha256 is None or args.verify_only, '--peer-sha256 requires --verify-only')
        snapshot, key = args.snapshot.resolve(), public_line(args.public_key)
        VERIFY.local_file(snapshot, 'kernel.txt')
        if not args.verify_only:
            prepare(snapshot, args, key)
        print(json.dumps(validate(snapshot, key, args.peer_sha256)))
        return 0
    except VERIFY.SnapshotError as error:
        print(json.dumps({'status': 'FAIL', 'error': str(error)}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
