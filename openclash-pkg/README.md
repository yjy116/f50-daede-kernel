# F50 OpenClash 0.47.167 + Mihomo v1.19.31

This builds two independently signed APKs from public, SHA256-pinned materials:

| Package | Version | Architecture | Content |
| --- | --- | --- | --- |
| luci-app-openclash | 0.47.167-r1 | noarch | Original OpenClash root/Lua files, compiled Simplified Chinese translation, package registration and notices |
| mihomo-openclash | 1.19.31-r1 | aarch64_generic | Unmodified official stable ARM64 core at `/etc/openclash/core/clash_meta`, GPL license and notice; no init service |

The UI requires exactly `mihomo-openclash=1.19.31-r1`. OpenClash is built from
commit `22abb8ec08f08aac7924ce3c9c15a75def70badb`; this is 0.47.167, not the
older prebuilt 0.47.156 release. The 205 source files are locked individually.
The three public archives and both installed licenses accompany the output.

## Native ARM64 cloud build

Run on an ARM64 GitHub runner such as `ubuntu-24.04-arm`. From the repository root:

```sh
docker build -f openclash-pkg/Dockerfile -t f50-openclash .
mkdir -p output
docker run --rm --platform linux/arm64 \
  -v "$PWD/output:/out" \
  -v "$PWD/kernel-evidence:/kernel:ro" \
  f50-openclash \
  --kernel-config /kernel/kernel.config \
  --kernel-validation /kernel/kernel-validation.json \
  --output /out
```

Supply the authenticated F50 kernel artifact directory as `kernel-evidence`;
the config SHA must match its validation report's `.config` artifact. The build
requires builtin `CONFIG_TUN=y` and `CONFIG_NFT_TPROXY=y`. No generic OpenWrt
kernel package is installed or fabricated. Use a fresh output directory for
each signing run. For offline materials, mount a read-only directory and pass
`--input-dir`; it must contain all three exact `filename` values in inputs.json.

The image runs contract tests with a 60-second hard timeout. The build verifies
all input SHA256 values, safe archive paths, 205 source-file hashes, the source
version and default enable=0. It compiles the original po2lmo C sources, executes
the real ARM64 core's `-v` and isolated direct-only configuration check (`-t`),
and checks AArch64 ELF with no interpreter or dynamic shared-library dependency.
The configuration check never starts a proxy listener.

Each APK is compared against its exact staged files, file permissions, ownership,
directories, scripts, metadata, dependencies and installed size, then verified
using only that run's generated public key. The private key lives in `/dev/shm`;
only APKs, public key, source archives, checksums and manifest are exported.
This is an F50 packaging signature, not an upstream-author or OpenWrt signature.

## Defaults and installation effects

- Upstream `openclash.config.enable=0` is preserved. No subscription, account,
  proxy configuration or private key is added. The packaged core has no service.
- Original UCI defaults are retained, including the firewall include, LuCI HTTP
  upload limit, uhttpd timeout/request settings and reload. Installation is not
  side-effect-free even while proxying is disabled; back up those configurations
  before the authorized device transaction.
- Source preinstall/prerm/postrm behavior is retained. OpenWrt registration adds
  normal default_postinst/default_prerm handling. `/etc/config/openclash` is
  registered as a conffile, with mode 0600; the complete source payload bytes
  remain unchanged. No updater/downloader behavior is silently disabled.
- Required userspace dependencies include dnsmasq-full, bash, curl, ca-bundle,
  ip-full, ruby, ruby-yaml, unzip, LuCI compatibility and rpcd-mod-file. Switching
  the installed dnsmasq variant is a separate reviewed transaction; no force or
  architecture bypass is part of this build.

## Kernel limitation

Mihomo commit `ab405bad5beeeac8b003bb01f60f134f6df54471`,
[`component/process/process_linux.go`](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/component/process/process_linux.go#L93),
uses INET_DIAG for TCP/UDP process attribution; it does not request RAW DIAG.
[`tunnel/tunnel.go`](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/tunnel/tunnel.go#L351)
logs a failed lookup and continues rule processing. `find-process-mode: off`
avoids lookup; default strict mode calls it when a process rule requires it.
F50 lacks UDP_DIAG, so UDP process/UID matching is not verified or promised.
This is not a mandatory core-startup, ordinary proxy-forwarding or TUN capability.
The package does not change the core or silently change the deployed process mode.

Local Windows checks validate contracts and original materials. Native ARM64
core execution, real APK generation/signature verification, device installation,
LuCI rendering and actual proxy traffic must be reported separately when run.
