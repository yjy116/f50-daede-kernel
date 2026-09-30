# Mainline WLAN RX software checksum patch

The pinned MU300 source contains this fix in the Android 5.4 patch directory,
but its mainline module builder copies `upstream/modules/sprd_wlan_combo`
directly. The 6.18.54 and 7.2.8 F50 builds previously missed this patch.

This build now applies the unchanged upstream patch to that actual mainline
source tree, before the vendor build copies it. Changed inputs, a failed Git
patch check/application, or unexpected output fail the build explicitly.

- Upstream commit: `1a69a41ea9d20fadd575e9b082364d61ce5fcf9a`
- [Patch source](https://github.com/dikeckaan/mu300-linux/blob/1a69a41ea9d20fadd575e9b082364d61ce5fcf9a/kernel/patches/wlan_combo-rx-software-checksum.patch)
- Patch SHA256: `a9b58f399781aa204550c1ff9829eb83c8db7193c0e40c5428c784572dd528cc`
- Original `sc2355/rx.c` SHA256: `de78047e7eac6c5b0e8dc68e0152359435b9d2e63a27bff5b845103eadf0dddb`
- Patched LF SHA256: `e15b3fd5e668fa247951601331759c9d73cbb4ed66bbe3e206c64a186794aa8e`

Patch application explicitly sets Git `core.autocrlf=false` and `core.eol=lf`.
Its output must match the single LF hash above; ambient Git line-ending settings
cannot change the bytes accepted for compilation. Regression tests exercise
both inherited autocrlf settings, including an inherited CRLF preference.

`sc2355_fill_skb_csum` sets `CHECKSUM_NONE` and returns zero, so the network
stack validates RX checksums in software instead of trusting incompatible
firmware checksum metadata. This addresses observed `hw csum failure` reports.
It does **not** establish that the separate daed/UDP kernel panic is fixed.

The output includes the exact patch/source hashes, copied compiled source,
final module helper disassembly and the real `sk_buff` BTF layout. Validation
requires the ARM64 helper to load the checksum byte, clear precisely the two
`ip_summed` bits, store that byte and return zero. BTI/NOP padding is accepted;
unexpected compiler output fails for review rather than skipping the check.
The existing kernel/module/BTF/eBPF validation remains required and unchanged.

The field location is also decoded from raw BTF whose hash is bound to the
same validated kernel. Anonymous struct/union offsets are accumulated; the
named `headers` alias is not treated as a second promoted member. Pahole's
duplicate aliases must all agree with that unique absolute location. Captured
6.18.54 and 7.2.8 output fixtures cover the actual byte 128, bit 5 layout and
the corresponding `0x9f` checksum mask; conflicting offsets fail validation.

Local tests apply the real upstream patch in temporary directories and reject
source drift, patch drift and repeat application. Disassembly parser fixtures
test the validation logic only; only the cloud build's real module and BTF
outputs can satisfy the artifact gate. Boot and Wi-Fi/proxy traffic validation
still require the F50 hardware.
