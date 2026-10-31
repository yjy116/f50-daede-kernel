"""Compare independently read boot bytes with the pre-write official bundle preview."""
import hashlib
import json
import tarfile
import zlib

from ssh_ops import PRIVATE, download, run

DISK = "/mnt/mu300-disk"
BOOT_PARTITION = "/dev/mmcblk0p38"
TIMEOUT = 120
BCB_OFFSET = 2048
BCB_BYTES = 32


def digest(data):
    return hashlib.sha256(data).hexdigest()


def check(condition, message):
    if not condition:
        raise ValueError(message)


def verify_misc():
    before = (PRIVATE / "before-misc.img").read_bytes()
    target = PRIVATE / "after-write-misc.img"
    download("dd if=/dev/mmcblk0p3 bs=1048576 2>/dev/null", target)
    actual = target.read_bytes()
    template = (PRIVATE / "trial-template.bin").read_bytes()
    check(len(template) == BCB_BYTES and template[:2] == b"_b", "Invalid slot template")
    check(template[14] == 0x2f, "Unexpected trial template")
    check(zlib.crc32(template[:28]).to_bytes(4, "little") == template[28:], "Template CRC differs")
    tries = int((PRIVATE / "boot-attempts.txt").read_text().strip())
    check(1 <= tries <= 6, "Unexpected configured trial count")
    body = bytearray(template[:28])
    body[14] = 0x0f | ((tries + 1) << 4)
    bcb = bytes(body) + zlib.crc32(body).to_bytes(4, "little")
    expected = before[:BCB_OFFSET] + bcb + before[BCB_OFFSET + BCB_BYTES:]
    check(actual == expected, "BCB trial differs or unrelated misc bytes changed")
    return {"sha256": digest(actual), "trial_count": tries, "changed_region": [2048, 2080]}


def main():
    expected = json.loads((PRIVATE / "official-expected-boot.json").read_text())
    image = PRIVATE / "after-write-boot_b.img"
    download("dd if=" + BOOT_PARTITION + " bs=1048576 2>/dev/null", image, timeout=TIMEOUT)
    data = image.read_bytes()
    check(len(data) == expected["partition_bytes"], "Boot read length differs")
    checks = {
        "body_sha256": digest(data[:expected["body_bytes"]]),
        "written_sha256": digest(data[:expected["written_bytes"]]),
        "footer_sha256": digest(data[expected["footer_offset"]:]),
    }
    for name, actual in checks.items():
        check(actual == expected[name], "Boot readback mismatch: " + name)
    with tarfile.open(PRIVATE / "before-boot-policy.tar.gz") as policy:
        locked = any(p.name.removeprefix("./").rstrip("/") == ".mu300/boot-lock" for p in policy)
    lock_test = "test -f" if locked else "test ! -e"
    script = f"""set -eu
cat {DISK}/boot/installed.id
cat {DISK}/boot/installed.kernel
cat {DISK}/boot/installed.tag
sha256sum /dev/mmcblk0p37 /dev/mmcblk0p3
{lock_test} {DISK}/.mu300/boot-lock
test "$(cat {DISK}/.mu300/boot-tries)" = 0
"""
    records = run(script, timeout=TIMEOUT).decode().splitlines()
    check(records[0] == expected["installed_id"], "Installed ID mismatch")
    check(records[1] == "7.2", "Installed kernel series mismatch")
    check(records[2] == "v2026.10.30.1", "Installed tag mismatch")
    before = json.loads((PRIVATE / "before-boot-verification.json").read_text())
    hashes = {"/dev/" + p["device"]: p["sha256"] for p in before["partitions"]}
    actual_hash, device = records[3].split()
    check(device == "/dev/mmcblk0p37" and actual_hash == hashes[device], "Android boot changed")
    misc = verify_misc()
    report = dict(status="PASS", reboot_performed=False, checks=checks,
                  installed_id=records[0], kernel=records[1], tag=records[2],
                  untouched_android_boot=records[3], misc=misc)
    (PRIVATE / "boot-write-verification.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
