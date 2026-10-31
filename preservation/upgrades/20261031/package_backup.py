"""Create an explicit encrypted recovery set; never publish plaintext or identities."""
import hashlib
import json
import subprocess
import tarfile
from pathlib import Path

from ssh_ops import HERE, PRIVATE

TAG = "f50-official-20261031"
PRIOR = HERE.parent / "github-config-20261011"
AGE = PRIOR / "age/age/age.exe"
KEYGEN = PRIOR / "age/age/age-keygen.exe"
IDENTITY = PRIOR / "private/recovery-key.txt"
ASSETS = HERE / "release-assets"
PROCESS_TIMEOUT = 180
EVIDENCE_FILES = (
    "candidate-validation.json", "boot-write-verification.json",
    "before-boot-verification.json", "pre-reboot-validation.log",
    "first-boot-runtime.log", "first-boot-hardware.log", "post-boot-identity-services.log",
    "post-boot-uci-difference-keys.json", "sim-post-reboot-runtime.log",
    "sim-final-system.log", "zerotier-target-probes.log", "zerotier-target-confirmed.log",
    "validated-metadata-verification.json", "validated-linux-restore.log",
    "validated-snapshot-device-readback.sha256", "maintenance-revocation.json",
)
EVIDENCE_DIRS = ("sim-test", "sim-proxy-initial", "sim-reboot-node-checks",
                 "sim-reboot-proxy", "sim-refreshed-node-checks", "sim-refreshed-proxy",
                 "sim-final-api")


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def recovery_inputs():
    files = []
    for source, prefix in ((PRIVATE / "official-validated-snapshot", "baseline"),
                           (PRIVATE / "pre-official-snapshot", "before-update")):
        files.extend((p, prefix + "/" + p.name) for p in sorted(source.iterdir()))
    for name in ("before-boot_a.img", "before-boot_b.img", "before-misc.img",
                 "before-boot-policy.tar.gz", "after-write-boot_b.img"):
        files.append((PRIVATE / name, "boot-recovery/" + name))
    for name in ("mu300-openwrt-luci-rootfs.tar.gz", "mu300-update", "SHA256SUMS",
                 "SHA256SUMS.sig", "release.pub", "mu300-release"):
        files.append((HERE / "official" / name, "official/" + name))
    files.append((HERE / "plugin-inputs/offline-inputs.tar", "plugins/offline-inputs.tar"))
    files.extend((PRIVATE / n, "evidence/" + n) for n in EVIDENCE_FILES)
    for name in EVIDENCE_DIRS:
        files.extend((p, "evidence/" + name + "/" + p.name)
                     for p in sorted((PRIVATE / name).iterdir()))
    if not all(p.is_file() and not p.is_symlink() for p, _ in files):
        raise ValueError("Recovery inputs must be explicit regular files")
    return files


def archive_and_encrypt():
    plaintext = PRIVATE / (TAG + ".tar.gz")
    files = recovery_inputs()
    with tarfile.open(plaintext, "x:gz", compresslevel=6) as output:
        for source, relative in files:
            output.add(source, arcname=relative, recursive=False)
    recipient = subprocess.run([str(KEYGEN), "-y", str(IDENTITY)], check=True,
                              capture_output=True, text=True, timeout=60).stdout.strip()
    ASSETS.mkdir(exist_ok=False)
    encrypted = ASSETS / (TAG + ".tar.gz.age")
    subprocess.run([str(AGE), "-r", recipient, "-o", str(encrypted), str(plaintext)],
                   check=True, timeout=PROCESS_TIMEOUT)
    restored = PRIVATE / (TAG + ".roundtrip.tar.gz")
    subprocess.run([str(AGE), "--decrypt", "-i", str(IDENTITY), "-o", str(restored), str(encrypted)],
                   check=True, timeout=PROCESS_TIMEOUT)
    if digest(restored) != digest(plaintext):
        raise ValueError("Encrypted backup round trip differs")
    return plaintext, encrypted, len(files)


def main():
    plaintext, encrypted, members = archive_and_encrypt()
    manifest = {
        "schema": 1, "tag": TAG, "upstream_release": "v2026.10.30.1",
        "upstream_commit": "8aadd074673a23a7e1e37fc07cfd1dd3a7773917",
        "kernel": "7.2.13", "package_count": 321, "archive_members": members,
        "asset": encrypted.name, "bytes": encrypted.stat().st_size,
        "sha256": digest(encrypted), "plaintext_sha256": digest(plaintext),
        "baseline_manifest_sha256": digest(PRIVATE / "official-validated-snapshot/SHA256SUMS"),
        "local_age_roundtrip": "PASS", "cellular_proxy_after_reboot": "PASS",
        "hotspot_client_user_confirmation": "PASS", "zerotier_remote_http": "PASS",
        "historical_intermittent_return_path_permanent_resolution": "NOT_PROVEN",
        "honk_argv_capture": "unavailable; comm mode; documented pname limitation",
        "secrets": "Only encrypted recovery archive; identity remains on maintenance computer",
    }
    (ASSETS / "release-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n",
                                                encoding="utf-8", newline="\n")
    rows = [f"{digest(p)}  {p.name}\n" for p in sorted(ASSETS.iterdir())]
    (ASSETS / "SHA256SUMS").write_text("".join(rows), encoding="ascii", newline="\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
