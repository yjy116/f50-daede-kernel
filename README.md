# F50 kernels with BTF and eBPF

Build Linux **6.18.54** and **7.2.8** for the ZTE F50/MU300 using GitHub Actions' native ARM64 runners. Both use the MU300 port at commit `1a69a41ea9d20fadd575e9b082364d61ce5fcf9a`, with an explicit configuration fragment for dae/daed capabilities.

The workflow is started manually from **Actions → F50 kernels with BTF and eBPF → Run workflow**. Each kernel is built independently, including all 31 matching vendor modules. Kernel tarballs, helper bundle and action revisions are pinned. Compiler and container details are recorded with the outputs.

Artifacts contain a project-format kernel bundle, the effective kernel configuration, the exact vmlinux BTF, compressed vmlinux, module symbol versions, validation results, compiler logs and SHA256 hashes. Failed builds retain diagnostics; an artifact from a failed run is not an installable release.

The release suffix is `-f50-dae1`. Network features are built in because the upstream packaging script only includes the vendor modules. Module debug information is removed with `--strip-debug` before packaging; module names, architecture and version are checked afterward. vmlinux BTF is mandatory; module split-BTF is not required for this profile.

The manual **F50 adapted networking packages** workflow repackages hash-pinned ZeroTier, daed and LuCI daede APKs for these built-in kernel features. It preserves upstream payloads and install scripts, changes only the reviewed dependency/version/description metadata, and verifies exact file and link contents. It consumes a fixed successful kernel build report and its matching full configuration. Each packaging run signs with a temporary container-only private key and exports only the packages, public key and audit manifest. This does not install anything; the running device and installation transaction still need separate verification. See [packaging instructions](packaging/USAGE.txt).

This repository contains build definitions and references to public sources. It does not contain device backups, device credentials, mobile configuration or a device-specific boot image. The workflow does not flash a device or publish a GitHub Release.

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
