# Persistent Tailscale VPN menu

Build from the repository root:

```sh
docker build -f vpn-menu-pkg/Dockerfile -t f50-vpn-menu .
mkdir -p artifacts
docker run --rm -v "$PWD/artifacts:/out" f50-vpn-menu --output /out
```

The two official OpenWrt 25.12.5 LuCI APKs are pinned in `inputs.json`.
They have no package signature; their metadata and payload hashes were verified
against the official signed LuCI index during the second-batch audit. The build
checks the exact input SHA256/size and never executes their lifecycle scripts.

The sole UI payload change is `usr/share/luci/menu.d/luci-app-tailscale-community.json`:
move `admin/services/tailscale` to `admin/vpn/tailscale` and register the `admin/vpn`
parent with `firstchild`, title VPN, order 45. Preserve the Tailscale child title,
order and `view/tailscale.js` action. All JS, rpcd ucode, ACLs and lifecycle scripts
stay byte-identical. The backend `tailscale` package is neither rebuilt nor changed.
The extracted menu/view/ucode/ACL files are scanned for old services references;
the build fails if any remain. The original files contain no other menu links.

Both package versions become `26.270.72870~a24d1f2-r1`; only the translation's UI
dependency changes to the exact paired UI version. Other dependencies and fields
are preserved, except the explicit adaptation description, derived identity hash,
and the exact menu-size delta. Strict audit checks all files, modes, owners,
timestamps, directories, scripts and remaining metadata. Original post-install
and post-upgrade already invalidate LuCI menu/module caches and reload rpcd.

Output APKs have one fresh signature. The private key exists only in container
`/dev/shm`, outside exported artifacts; public key, two APKs, menu diff, manifest
and SHA256SUMS are exported. Native apk-tools 3.0.8 verifies outputs with only
that public key. Host extraction of pinned unsigned inputs uses
`apk extract --allow-untrusted`; no device installation bypass is provided.

Unit tests cover menu preservation and rejection of payload/script/metadata
changes. Actual APK construction and verification require the Linux container;
no device installation or browser/runtime check is claimed by this packager.
