F50 configuration preservation profile / 2026-10-31

Capture CURRENT settings before each upgrade:
  /etc/mu300/f50-profile/capture.sh /root/f50-snapshots/<unique-name>
The capture briefly stops Honk for a consistent SQLite database and WAL, then
restores its running state. A nonzero exit or INCOMPLETE marker is a failure.
Copy the snapshot to the maintenance computer and verify schema1, hashes,
ownership, links and SQLite; also restore into an isolated Linux directory.
Exclude only the exact temporary maintenance authorization from permanent copies.

Current system: official v2026.10.30.1 / OpenWrt 25.12.6 / official kernel 7.2.13.
Honk f50-sipa1 and Doona beta.19 retain the current accounts, subscriptions and
settings. OpenClash remains disabled. The user permits daede only if Honk proves
incompatible. After SIM insertion, all three nodes passed HTTP and UDP DNS.
After a further normal reboot with SIM inserted (new boot ID), WAN came up
automatically and all six node HTTP/UDP DNS checks passed again. Google returned
204 and ipify 200 with proxy/reply_received flow evidence in both stages.
The owner disabled mobile data on the phone, connected to F50, and confirmed
Google, LuCI temperature, the Doona entry and traffic page worked normally.
The official kernel still lacks Honk's full argv path; pname_routing_reduced
remains visible. Proxy traffic checks do not prove full process-name routing.

Use complete signed official images and official BPF JIT/BTF kernels for future
upgrades. Do not compile another kernel or reinstall the old custom kernel as
normal maintenance. Old snapshots remain available for an explicit rollback.
Install compatible signed plugin dependencies into a separate candidate before
official carry, preserve service choices, and review first-boot defaults.
Keep the new official mu300-hw and system metadata. Do not overwrite all of /etc
or restore an old APK database. Preserve current user changes over older baselines.
The official ADB control /etc/mu300/adb is off to retain the prior USB behavior.
The computer keeps WLAN internet; USB is only F50 management.

LuCI keep.d integration expands configuration backups only. It does not intercept
mu300-update or guarantee arbitrary manual flashing preserves custom files.
The official updater also writes boot; verify the whole operation before reboot.

Official kernel bundle: /mnt/mu300-disk/f50-official-20261031/mu300-kernel-7.2.tar.gz
SHA256: f52f3e043ea5fc6cb58e187a7643a35053b5eda1ad7b5c9de71ae8feae9ff03a
This is a permanent dependency of capture.sh, not disposable staging data.
Captures verify and copy the bundle named by kernel-bundle.sha256 and require its
kernel.release to match uname. Update the profile when changing official kernels.

After future migrations, repeat config/identity, SQLite, module, kernel-feature,
Honk API, thermal ACL/menu, Wi-Fi and real SIM/HTTP/UDP DNS/hotspot proxy checks.
This upgrade passed the real-network and reboot checks above; the historical
intermittent cellular return-path loss is not proven permanently resolved.

Snapshot metadata tools (run on the maintenance computer):
  python final_snapshot_metadata.py SNAPSHOT_DIR --public-key MAINTENANCE_KEY.pub
The new tool supports the official 7.2.13 profile and schema1 verification.
It uses --kernel PATH or tools/official/mu300-kernel-7.2.tar.gz, and requires the
exact official SHA above. Install cryptography==50.0.2 in a private Python venv.
Only the exact public-key authorization line is removed; other authorization
bytes and archive members are verified unchanged. Default expected line count
is 1; use --expected-key-count 0 explicitly for capture after key revocation.
It verifies a temporary copy before committing finalized files, retains the
capture-device-archives.sha256 provenance, and regenerates clean archive and
artifact SHA manifests plus restore-metadata.tsv (path, mode, uid, gid; no header).
A failed/interrupted commit retains INCOMPLETE and must not be treated as valid.

After synchronizing finalized artifacts to the device, obtain actual device
hashes for every SHA256SUMS entry plus SHA256SUMS itself, with relative filenames.
Recheck locally:
  python final_snapshot_metadata.py SNAPSHOT_DIR --public-key MAINTENANCE_KEY.pub --verify-only --peer-sha256 DEVICE_READBACK.sha256
This verifies hashes and schema1 virtual restore; perform the separate Linux
isolated restore for real modes/owners/links. The tool does not revoke live or
rollback-root SSH access: remove that exact authorization from both separately.

finalize_snapshot.py remains the unchanged historical 2026-10-11 implementation,
including its old key comment/kernel SHA. Do not use it for new official captures.
The existing f50-profile-20261011 Release and its attachments remain unchanged;
new encrypted backups require their own version tag. verify-device-restore.sh
also retains historical fixed paths: adapt a reviewed copy for the new isolated
restore directory, never point it at the running root.

Run all three test files under a 60-second hard timeout per process. The new
focused tests reuse test_verify_snapshot.py fixtures and need the real official
bundle in tools/official; this directory is gitignored and is not committed.
CI downloads the pinned v2026.10.30.1 bundle and verifies its SHA before testing.
