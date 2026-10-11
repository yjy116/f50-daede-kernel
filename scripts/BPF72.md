# Linux 7.2.9 candidate with BPF JIT/BTF

The manual `build-kernel-72-bpf.yml` workflow uses MU300 release `v2026.10.17`
at commit `d033b55b5c9d2566a72037118c5fe5cd5707f3fe`. It builds
`7.2.9-f50-bpf1`, preserving the original workflows and `-f50-dae1` artifacts.
The tarball, reference kernel bundles and Actions are hash pinned in the source.

The upstream build scripts and bundle packager are used directly. Their current
WLAN checksum, WCN recovery, boot-slot and SD support are retained; the old WLAN
source patch is not reapplied. `config/bpf72.config` replaces only its listed
configuration keys. It enables BPF JIT, kernel BTF and tracing. Honk's BPF/cgroup/
TC/network-namespace and NFQUEUE requirements are checked in the final config.
`NET_ACT_BPF`, `NFT_QUEUE` and `NETFILTER_NETLINK_QUEUE` remain modules. The
candidate must contain exactly 379 modules, with matching architecture, internal
module names and new vermagic. vmlinux BTF is decoded with pahole and exported
separately.

The pinned official bundle has 376 filenames, but three entries contain the
opposite-case module's payload: `xt_dscp.ko` contains `name=xt_DSCP`, `xt_HL.ko`
contains `name=xt_hl`, and `xt_tcpmss.ko` contains `name=xt_TCPMSS`. Both the official
and candidate configs select all six corresponding `NETFILTER_XT_MATCH_*` and
`NETFILTER_XT_TARGET_*` options as modules. Native Linux therefore builds all six;
this repairs the release's case-collision loss rather than adding new options.
`prepare-reference` verifies all 376 ELF identities, records precisely these three
known mismatches, and derives the strict 379-name candidate inventory. Candidate
and package checks reject any missing/extra name, internal-name mismatch or
payload mismatch. Keep module archives intact on case-insensitive filesystems.

The ARM64 static `bpf72-probe` is compiled before the kernel. On the F50 it checks
map operations, SOCKET_FILTER/SCHED_CLS load and JIT, an isolated socket-filter
test run, and the running kernel's BTF header. It attaches no network hooks.
Run it as root with an external timeout after verifying the artifact SHA256:

```sh
timeout 15 /root/bpf72-probe
```

Local gates (unit tests have a 60-second external deadline in Actions):

```sh
timeout 60s python3 -m unittest discover -s scripts -p 'test_bpf72*.py' -v
bash -n scripts/build-bpf72.sh
```

Trigger after review and push:

```sh
gh workflow run build-kernel-72-bpf.yml --ref main
```

Only a successful Actions run with PASS kernel and bundle reports is a build
candidate. Failed jobs upload diagnostics too; their artifacts must not be
installed. Build checks do not prove hardware boot, BPF program load on this
board, CO-RE compatibility, or Honk/dae traffic. Preserve the verified official
7.2.9 boot image and its modules for rollback, then validate the assembled boot
image, flash/readback, boot, USB, Wi-Fi, BTF, probe and application traffic.
This profile does not claim to fix the previously observed dae UDP panic.
