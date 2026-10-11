#!/usr/bin/env bash
set -euo pipefail

build_root=$(cd "$(dirname "$0")" && pwd)
source "$build_root/build.env"
source_root=${1:?usage: ablation.sh SOURCE ARTIFACTS}
artifacts=${2:?usage: ablation.sh SOURCE ARTIFACTS}
cd "$source_root"
common_source=crates/honk-ebpf-common/src/sipa.rs
core_source=crates/honk-core/src/ebpf/real/sipa.rs
trap 'git restore --worktree -- "$common_source" "$core_source"' EXIT
git apply --check "$build_root/sipa-production-ablation.patch"
git apply "$build_root/sipa-production-ablation.patch"
git diff --binary > "$artifacts/production-ablation.patch"
mkdir -p "$artifacts/ablation-common" "$artifacts/ablation-core"

cargo test --locked --no-run -p honk-ebpf-common --lib \
  --message-format=json > "$artifacts/ablation-common/test-compile.jsonl"
python3 "$build_root/run-tests.py" "$artifacts/ablation-common" \
  sipa::tests::native_sipa_ipv4_and_ipv6_keep_ethernet_header --ablation
cargo test --locked --no-run -p honk-core --lib --no-default-features \
  --features "$HONK_FEATURES" --message-format=json > "$artifacts/ablation-core/test-compile.jsonl"
python3 "$build_root/run-tests.py" "$artifacts/ablation-core" \
  ebpf::real::sipa::tests::verified_f50_sipa_selects_mixed_rx_and_ethernet_tx --ablation
