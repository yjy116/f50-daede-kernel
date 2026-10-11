#!/usr/bin/env bash
set -euo pipefail

build_root=$(cd "$(dirname "$0")" && pwd)
source "$build_root/build.env"
source_root=${1:?usage: prepare.sh SOURCE ARTIFACTS}
artifacts=${2:?usage: prepare.sh SOURCE ARTIFACTS}
mkdir -p "$artifacts"
cd "$source_root"

test "$(git rev-parse HEAD)" = "$HONK_REVISION"
test -z "$(git status --porcelain)"
git apply --index --check "$build_root/honk-sipa.patch"
git apply --index "$build_root/honk-sipa.patch"
git diff --cached --check
git diff --cached --binary > "$artifacts/applied.patch"
test -s "$artifacts/applied.patch"
cp "$build_root/build.env" "$artifacts/"
cp "$build_root/honk-sipa.patch" "$artifacts/"
git rev-parse HEAD > "$artifacts/upstream-revision.txt"
git -C "$build_root" rev-parse HEAD > "$artifacts/build-revision.txt"
source .github/ci/pins.env
test "$DOONA_VERSION" = 0.1.0-beta.19
test "$DOONA_REVISION" = 2391fb7b622e180243aa71b2da5274566432683e
test "$DOONA_SHA256" = 5500c2f630bb6cadaa7c2db5758f9ffca3ca86fb47e63e4f145b6bf461173a04
cp .github/ci/pins.env "$artifacts/upstream-pins.env"

curl -fsSL --retry 3 -o "$RUNNER_TEMP/bpf-linker.tar.zst" \
  "https://github.com/aya-rs/bpf-linker/releases/download/v$BPF_LINKER_VERSION/bpf-linker-x86_64-unknown-linux-musl.tar.zst"
echo "$BPF_LINKER_SHA256  $RUNNER_TEMP/bpf-linker.tar.zst" | sha256sum -c -
zstd -dc "$RUNNER_TEMP/bpf-linker.tar.zst" | tar -xf - -C "$CARGO_HOME/bin"
bpf-linker --version | tee "$artifacts/bpf-linker-version.txt"
doona_dir=$(ci/fetch-doona.sh)
printf 'HONK_DOONA_DIR=%s\n' "$doona_dir" >> "$GITHUB_ENV"
printf 'SOURCE_DATE_EPOCH=%s\n' "$(git show -s --format=%ct HEAD)" >> "$GITHUB_ENV"

cd crates/honk-ebpf
cargo build --locked --release -Zbuild-std=core --target bpfel-unknown-none
readelf -SW target/bpfel-unknown-none/release/honk-ebpf > "$artifacts/ebpf-sections.txt"
grep -q '\.BTF ' "$artifacts/ebpf-sections.txt"
readelf -sW target/bpfel-unknown-none/release/honk-ebpf > "$artifacts/ebpf-symbols.txt"
grep -Eq '[[:space:]]wan_ingress_sipa$' "$artifacts/ebpf-symbols.txt"
printf '%s' "$EBPF_RUST_VERSION" > target/bpfel-unknown-none/release/honk-ebpf.toolchain
