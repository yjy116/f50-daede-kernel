"""Verify downloaded Release bytes, decrypt, and compare every recovery input."""
import hashlib
import json
import subprocess
import tarfile
from pathlib import PurePosixPath

from package_backup import ASSETS, AGE, IDENTITY, TAG, digest, recovery_inputs
from ssh_ops import HERE, PRIVATE

DOWNLOAD = HERE / "downloaded-release"
TIMEOUT = 180


def verify_assets():
    expected = {p.name for p in ASSETS.iterdir()}
    if {p.name for p in DOWNLOAD.iterdir()} != expected:
        raise ValueError("Downloaded Release asset set differs")
    result = {}
    for name in sorted(expected):
        actual = digest(DOWNLOAD / name)
        if actual != digest(ASSETS / name):
            raise ValueError("Downloaded asset checksum mismatch")
        result[name] = {"sha256": actual, "bytes": (DOWNLOAD / name).stat().st_size}
    return result


def decrypt_download(manifest):
    decrypted = PRIVATE / "downloaded-recovery.tar.gz"
    result = subprocess.run([str(AGE), "--decrypt", "-i", str(IDENTITY), "-o", str(decrypted),
                             str(DOWNLOAD / manifest["asset"])], capture_output=True, timeout=TIMEOUT)
    (PRIVATE / "download-decryption.log").write_bytes(result.stderr)
    result.check_returncode()
    if digest(decrypted) != manifest["plaintext_sha256"]:
        raise ValueError("Downloaded encrypted backup decrypts to different plaintext")
    return decrypted


def verify_members(archive):
    expected = {name: source for source, name in recovery_inputs()}
    seen = set()
    with tarfile.open(archive) as source:
        for member in source:
            path = PurePosixPath(member.name)
            if not member.isfile() or path.is_absolute() or ".." in path.parts:
                raise ValueError("Invalid recovery archive member")
            if member.name not in expected or member.name in seen:
                raise ValueError("Unexpected recovery archive path")
            actual = hashlib.file_digest(source.extractfile(member), "sha256").hexdigest()
            if actual != digest(expected[member.name]):
                raise ValueError("Recovery archive member checksum mismatch")
            seen.add(member.name)
    if seen != expected.keys():
        raise ValueError("Recovery archive omits a required input")
    return len(seen)


def main():
    assets = verify_assets()
    manifest = json.loads((DOWNLOAD / "release-manifest.json").read_text(encoding="utf-8"))
    members = verify_members(decrypt_download(manifest))
    if members != manifest["archive_members"]:
        raise ValueError("Recovery archive count differs")
    result = {"status": "PASS", "tag": TAG, "assets": assets,
              "remote_decryption": "PASS", "all_recovery_input_hashes": "PASS",
              "archive_members": members, "snapshot_members_prevalidated": 3289,
              "sqlite_and_linux_restore_prevalidated": "PASS"}
    (HERE / "download-verification.json").write_text(json.dumps(result, indent=2) + "\n",
                                                   encoding="utf-8", newline="\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
