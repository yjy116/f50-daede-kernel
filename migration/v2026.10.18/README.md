# One-time v17 to v18 userspace migration record

This is the unchanged historical procedure used for one F50 on 2026-10-11:
mu300-linux `v2026.10.17` to `v2026.10.18`, retaining kernel
`7.2.9-f50-bpf1`, Honk `f50-sipa1`, its embedded Doona, the thermal integration,
and user settings. It is not a general-purpose updater, an installation package,
or a procedure to run again on the already upgraded device.

## Public record

The five shell files were copied byte-for-byte from the reviewed migration:

- `preflight-v18.sh`: prepare the delta and capture rollback material.
- `apply-v18.sh`: install the signed socket dependency, replace the 38 selected
  upstream items, then publish the new version marker.
- `rollback-v18.sh`: manual rollback using that transaction's saved inputs.
- `deploy-common.sh`: fixed staging path, local APK options and checks.
- `verify-v18-runtime.sh`: read-only runtime acceptance with a 60-second timeout.

The four accompanying input records contain paths, modes, owners, public
artifact hashes and absence markers, not configuration values:

- `userspace-migration-manifest.json`: all 45 upstream differences, including
  38 copied items, five APK-transaction items and two generated TLS items to keep.
- `v18-target-files.sha256`: the 34 regular-file targets.
- `v18-target-links.tsv`: the four upstream symlink targets.
- `live-targets-before.txt`: the 38 reviewed target states before this migration;
  only application-code/metadata paths and their hashes are listed.

All 45 target entries were checked against the original public v18 rootfs.
The device-generated preserved-config manifest and rollback archives are not
published here. `SHA256SUMS` covers the public copies and this README:

```sh
sha256sum -c SHA256SUMS
```

## Fixed inputs and dependencies

The original source revisions were
`d033b55b5c9d2566a72037118c5fe5cd5707f3fe` (v17) and
`119f68c5db6ef79fa0fab319d2aabee132183812` (v18) in
[mu300-linux](https://github.com/dikeckaan/mu300-linux).
The v18 `mu300-openwrt-luci-rootfs.tar.gz` SHA-256 was
`a3c5247516d3251d5a762d16e8acbbef0cf04eeae59f22cd59b0d0d8b668cb94`.

The scripts expect `/root/f50-v18-20261011` and do not relocate themselves.
They also require the original `v18-userspace-payload.tar.gz`, the signed local
socket repository (`socket-package/packages.adb` and its matching APK), the
device's trusted OpenWrt key, and transaction-specific backup/verification files.
Those artifacts are not bundled in this source directory. The payload and
socket inputs have pinned hashes in `preflight-v18.sh`; downloading a later
repository index or repacking a tarball does not reproduce those bytes.

The only added package was `ucode-mod-socket=2026.01.16~85922056-r2`; existing
`libc=1.2.5-r5` and `ucode=2026.01.16~85922056-r2` satisfied its dependencies.
Installation uses the signed index, existing trusted keys and `--no-network`,
without `--allow-untrusted`. APK owns package state; the migration does not
replace the installed database with the image's database. `apk-before.tar`
was captured as recovery evidence, not blindly restored across versions.

The runtime verifier additionally requires the F50's bundled BusyBox, `jq`,
`ucode`, `ubus`, `curl`, kernel sysfs/procfs interfaces and the private preserved
manifest. It fixes the 38-target count, 436 non-boot preservation entries,
binary/kernel hashes, `sipa_eth0`, Doona address, and boot partition geometry
to this specific baseline.

## Limits that remain part of the historical record

The preflight/apply preservation check hashes the whole boot partition and is
only a same-boot invariant. The boot init writes persistent logs at 48-56 MiB;
the runtime verifier instead checks the pinned effective image body and final
64-byte footer. A later rollback needs a reviewed recovery plan rather than
refreshing the old whole-partition hash to conceal that distinction.

The preflight's `/etc/mu300/traffic.conf` absence check alone does not cover the
traffic service's shared `.mu300/traffic/conf` state. The original acceptance
also inspected actual runtime settings: traffic CAP/CUT were zero, and no CPU
profile, traffic limit or SMS forwarding was enabled by this migration.

The runtime script checks LuCI login enforcement, public UI/static resources,
RPC and services; it does not authenticate to Doona or prove proxy traffic.
Real phone/proxy and node-connectivity checks were separate device acceptance.
Intermittent cellular return-path loss across reboot was not established as
fixed by v18. No firmware flash or migration is triggered by these public files.

These maintenance scripts and manifests are historical local work. Referenced
upstream rootfs/package content retains its original license; this source
record does not relicense or redistribute those binary payloads.
