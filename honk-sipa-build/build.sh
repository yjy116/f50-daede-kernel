#!/usr/bin/env bash
set -euo pipefail

build_root=$(cd "$(dirname "$0")" && pwd)
source "$build_root/build.env"
source_root=${1:?usage: build.sh SOURCE ARTIFACTS MODE}
artifacts=${2:?usage: build.sh SOURCE ARTIFACTS MODE}
mode=${3:?usage: build.sh SOURCE ARTIFACTS MODE}
cd "$source_root"
export GITHUB_REF="refs/tags/$HONK_BUILD_VERSION"
rustc -Vv > "$artifacts/rustc.txt"
cargo -V > "$artifacts/cargo.txt"
zig version > "$artifacts/zig.txt"

case "$mode" in
  test)
    cargo fmt --all --check
    cargo fmt --manifest-path crates/honk-ebpf/Cargo.toml --check
    mkdir -p "$artifacts/common" "$artifacts/core"
    cargo test --locked --no-run -p honk-ebpf-common --lib \
      --message-format=json > "$artifacts/common/test-compile.jsonl"
    python3 "$build_root/run-tests.py" "$artifacts/common" "$HONK_COMMON_TEST_FILTER"
    cargo test --locked --no-run -p honk-core --lib --no-default-features \
      --features "$HONK_FEATURES" --message-format=json > "$artifacts/core/test-compile.jsonl"
    python3 "$build_root/run-tests.py" "$artifacts/core" "$HONK_TEST_FILTER"
    bash "$build_root/ablation.sh" "$source_root" "$artifacts"
    ;;
  build)
    export ZIGCC_TARGET=aarch64-linux-musl
    export CC_aarch64_unknown_linux_musl="$PWD/ci/zigcc"
    export CXX_aarch64_unknown_linux_musl="$PWD/ci/zigcxx"
    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$PWD/ci/zigcc"
    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS='-C link-self-contained=no'
    BINDGEN_EXTRA_CLANG_ARGS=$(ci/zig-bindgen-env "$ZIGCC_TARGET")
    export BINDGEN_EXTRA_CLANG_ARGS
    cargo build --locked --release -p honk-core --no-default-features \
      --features "$HONK_FEATURES" --target "$HONK_TARGET"
    bash "$build_root/package.sh" "$source_root" "$artifacts"
    ;;
  *) printf 'Unknown mode: %s\n' "$mode" >&2; exit 1 ;;
esac
