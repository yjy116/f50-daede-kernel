# Historical F50 integration files

These six reviewed source files were exported from the sanitized private F50
configuration baseline captured on 2026-10-11. The baseline used mu300-linux
`v2026.10.18`, kernel `7.2.9-f50-bpf1`, Honk
`debug.2026.10.9.native-api.2-f50-sipa1`, and embedded Doona `0.1.0-beta.19`.
This directory is a historical source reference, not an automatic installer or
a complete device backup.

Only the following archive members were read for this export:

| Root-relative path | Purpose |
| --- | --- |
| `etc/init.d/honk` | procd startup, module requirements and graceful shutdown |
| `etc/init.d/mu300-hw` | preserve configured AP state while waiting for WCN setup |
| `usr/share/rpcd/acl.d/luci-f50-thermal.json` | narrowly scoped thermal reads |
| `www/luci-static/resources/view/status/include/15_f50_thermal.js` | six sensor readings on the LuCI overview |
| `usr/share/luci/menu.d/luci-app-doona.json` | LuCI menu registration |
| `www/luci-static/resources/view/services/doona.js` | link to the Doona management UI |

`rootfs/` preserves their original bytes, including UTF-8 text. The accompanying
`source-manifest.json` records each original SHA-256, size, mode and owner. Git on
Windows does not reproduce Linux owner IDs; the manifest is the permission
record. `SHA256SUMS` checks the public files from this directory:

```sh
sha256sum -c SHA256SUMS
```

No Honk configuration, authentication database, subscription, SSH key, device
certificate, network configuration, or boot image was exported. The public
files were checked before writing; the private source archive is not included.

## Runtime assumptions

The Honk init script requires its matching binary, configuration, geodata,
`nfnetlink_queue`/`nft_queue` support, procd, and the compatible custom kernel.
These files do not contain or create a working proxy configuration. The LuCI
link is intentionally unchanged and points at `http://192.168.77.1:9527/ui/`;
changing the device address requires reviewing that integration. Sensor names,
WCN module names, and regulatory setup are specific to this F50 baseline.

Review and merge against the destination system before any installation.
Preserve current user settings and service enable/disable state. The snapshot
and upgrade procedure is separate; stock `mu300-update apply` does not consume
the custom backup list and can update boot. This export does not claim that
intermittent cellular return-path loss after reboot has been fixed.

## Provenance and licenses

`mu300-hw` is a locally modified derivative of
[mu300-linux's hardware init script](https://github.com/dikeckaan/mu300-linux/blob/119f68c5db6ef79fa0fab319d2aabee132183812/openwrt/overlay/etc/init.d/mu300-hw).
The upstream [MIT license](https://github.com/dikeckaan/mu300-linux/blob/119f68c5db6ef79fa0fab319d2aabee132183812/LICENSE),
including its copyright notice, is reproduced verbatim in
`LICENSE.mu300-linux`. The local version is explicitly marked here as modified;
it is not presented as an unmodified upstream release file.

The other files are local integration source from this maintenance task, not
the Honk or Doona application source. Existing notices and upstream component
licenses remain applicable; publication of these integration files does not
relicense any third-party component. Honk/Doona build provenance and the
corresponding source/notices are documented separately in `../honk-sipa-build/`.
