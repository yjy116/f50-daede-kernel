#!/usr/bin/env bash
set -euo pipefail

build_root=$(cd "$(dirname "$0")" && pwd)
source "$build_root/build.env"
source_root=${1:?usage: package.sh SOURCE ARTIFACTS}
artifacts=${2:?usage: package.sh SOURCE ARTIFACTS}
cd "$source_root"
binary="target/$HONK_TARGET/release/honk-core"
file "$binary" | tee "$artifacts/elf-file.txt"
readelf -h "$binary" > "$artifacts/elf-header.txt"
readelf -lW "$binary" > "$artifacts/elf-program-headers.txt"
readelf -dW "$binary" > "$artifacts/elf-dynamic.txt"
grep -q 'Machine:.*AArch64' "$artifacts/elf-header.txt"
grep -q 'Class:.*ELF64' "$artifacts/elf-header.txt"
if grep -q INTERP "$artifacts/elf-program-headers.txt" || grep -q NEEDED "$artifacts/elf-dynamic.txt"; then
  echo 'Expected a static binary without an interpreter or shared-library dependency.' >&2
  exit 1
fi
timeout 60s qemu-aarch64 "$binary" --version | tee "$artifacts/version.txt"
grep -Fq "$HONK_BUILD_VERSION" "$artifacts/version.txt"

package="$artifacts/honk-core-f50-sipa1-aarch64-musl-stock"
mkdir -p "$package/doona"
cp "$binary" LICENSE README.md "$package/"
cp -r "$HONK_DOONA_DIR"/{LICENSE,LICENSES,NOTICE,THIRD-PARTY-NOTICES.txt} "$package/doona/"
tar -czf "$artifacts/honk-core-f50-sipa1-aarch64-musl-stock.tar.gz" \
  -C "$artifacts" "$(basename "$package")"
git archive --format=tar --prefix=honk/ "$HONK_REVISION" | gzip -n > "$artifacts/honk-base-source.tar.gz"
bash ci/fetch-doona.sh --source "$artifacts"
git -C "$build_root/.." archive --format=tar HEAD \
  honk-sipa-build .github/workflows/honk-sipa.yml | gzip -n > "$artifacts/build-definitions.tar.gz"
sha256sum "$binary" crates/honk-ebpf/target/bpfel-unknown-none/release/honk-ebpf \
  Cargo.lock crates/honk-ebpf/Cargo.lock > "$artifacts/compiled-inputs-sha256.txt"
cd "$artifacts"
sha256sum ./*.tar.gz ./*.patch ./build.env ./upstream-pins.env \
  ./upstream-revision.txt ./build-revision.txt > SHA256SUMS
sha256sum -c SHA256SUMS
