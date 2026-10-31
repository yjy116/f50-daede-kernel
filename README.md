# F50 official updates and configuration preservation

The device booted **official mu300-linux v2026.10.30.1 / OpenWrt 25.12.6 /
Linux 7.2.13**, with BPF JIT enabled, runtime BTF, and 321 installed packages.
The existing SIPA-adapted Honk core and Doona beta.19 remain in place.
See the [2026-10-31 upgrade report](preservation/releases/f50-official-20261031.md)
for the pinned official artifacts, configuration migration, boot readback and
validation limits. After SIM insertion, all three nodes passed HTTP and independent
UDP DNS probes. A subsequent reboot with the SIM inserted produced a new boot ID,
automatic WAN recovery, and another pass of all six probes. Google and ipify
requests also had complete proxy-flow reply evidence. With mobile data disabled,
the owner confirmed Google, LuCI temperatures, Doona and the traffic page over F50 Wi-Fi.
Honk also reports `pname_routing_reduced`: the official kernel lacks its full
process-argument observation facilities. The configured `zerotier-one` name equals
its observed short `comm` name; this does not establish support for long names or
argv-dependent rules. The subscription refreshed successfully after an initial
pre-WAN stale state, changing runtime node IDs; all six node probes and both proxy
requests passed again using the refreshed IDs. A temporary ZeroTier next-hop ARP
failure recovered without service or firewall changes, with both reported targets
passing ping and HTTP on retest. The final `official-validated-20261031` capture is
complete, with 3,289 members, SQLite integrity, Linux isolated restore and both-side hashes verified.
The encrypted recovery package passed a local age round trip; see the
[f50-official-20261031 release](https://github.com/yjy116/f50-daede-kernel/releases/tag/f50-official-20261031)
for attachment publication and download-verification records. One successful reboot does
not prove that the historical intermittent return-path failure is permanently fixed.

Future maintenance uses complete official rootfs updates and an official kernel
that already provides BPF JIT/BTF. This device's maintenance plan no longer
compiles or deploys the historical custom kernels in this repository. If Honk
proves incompatible, the owner permits migration to a verified daede setup;
this update has not made that change. OpenClash remains installed and disabled.
Follow [UPGRADE-POLICY.md](preservation/UPGRADE-POLICY.md) and
[preservation/README.md](preservation/README.md). Each new encrypted backup uses
its own release tag; the existing `f50-profile-20261011` release is retained.

## Historical build workflows

The following workflows and custom sources are retained for traceability, not as
instructions for the current device's next upgrade.

The historical independent [7.2.9 BPF/JIT/BTF candidate](scripts/BPF72.md) builds
MU300 `v2026.10.17` with 379 modules and suffix `-f50-bpf1`, repairing three
case-colliding module pairs in the official 376-file bundle.
Its manual workflow is **F50 Linux 7.2.9 BPF JIT and BTF**; the historical builds
below remain available unchanged.

The earlier workflow built Linux **6.18.54** and **7.2.8** for the ZTE F50/MU300 using GitHub Actions' native ARM64 runners. Both use the MU300 port at commit `1a69a41ea9d20fadd575e9b082364d61ce5fcf9a`, with an explicit configuration fragment for dae/daed capabilities.

The workflow is started manually from **Actions → F50 kernels with BTF and eBPF → Run workflow**. Each kernel is built independently, including all 31 matching vendor modules. Kernel tarballs, helper bundle and action revisions are pinned. Compiler and container details are recorded with the outputs.

Artifacts contain a project-format kernel bundle, the effective kernel configuration, the exact vmlinux BTF, compressed vmlinux, module symbol versions, validation results, compiler logs and SHA256 hashes. Failed builds retain diagnostics; an artifact from a failed run is not an installable release.

The release suffix is `-f50-dae1`. Network features are built in because the upstream packaging script only includes the vendor modules. Module debug information is removed with `--strip-debug` before packaging; module names, architecture and version are checked afterward. vmlinux BTF is mandatory; module split-BTF is not required for this profile.

The manual **F50 adapted networking packages** workflow repackages hash-pinned ZeroTier, daed and LuCI daede APKs for these built-in kernel features. It preserves upstream payloads and install scripts, changes only the reviewed dependency/version/description metadata, and verifies exact file and link contents. It consumes a fixed successful kernel build report and its matching full configuration. Each packaging run signs with a temporary container-only private key and exports only the packages, public key and audit manifest. This does not install anything; the running device and installation transaction still need separate verification. See [packaging instructions](packaging/USAGE.txt).

Git tracks reviewed source, public references and non-secret validation summaries.
Complete device settings and recovery materials are stored only in an **age-encrypted
Release attachment**; no plaintext credentials, subscriptions or device private
keys are committed. The recovery key is retained privately by the owner. Kernel
build workflows do not flash a device or publish a GitHub Release.

A successful build proves the recorded build checks only. Before installation, verify the complete device-specific boot image layout and keep a working rollback image. Hardware boot, USB, Wi-Fi, eBPF loading and actual proxy traffic still require tests on the F50. Stock OpenWrt 6.12 kernel modules and unrelated BTF packages must not be substituted for this kernel's own outputs.

The separate manual **F50 load-only BPF diagnostic** workflow builds a static ARM64 `bpf-probe`. It loads small TC/cgroup programs, including `bpf_loop` callbacks with their required program-local BTF and function metadata, reads their JIT information and closes each program and BTF descriptor. It does not attach or execute a program, create maps or network namespaces, or pin objects. A pass proves only these load/JIT checks, not vmlinux BTF availability, CO-RE relocation or the complete dae datapath. Run with Linux BPF privileges and a short external timeout; `--help` is available without BPF access.

Sources: [MU300 port](https://github.com/dikeckaan/mu300-linux), [dae requirements](https://github.com/daeuniverse/dae/blob/main/docs/en/README.md), [OpenWrt daede packaging](https://github.com/kenzok8/openwrt-daede).

The manual **F50 Chinese ZeroTier LuCI** workflow builds a paired p2 backend and
Chinese UI for an existing F50 p1 installation. It adds per-network enable and
owned firewall4 controls, configuration paths, and interface status while keeping
the original ZeroTier 1.16.0 executable. The UI uses native LuCI controls styled
by the active theme, including the reference device's public Aurora theme, and
retains the current identity when its replacement field is blank. Installation
does not join a network or start the daemon. Every backend payload change is
explicitly listed and audited; generated firewall rules do not rewrite users'
persistent firewall zones. See [UI build and behavior notes](zerotier-ui/BUILD.txt).
