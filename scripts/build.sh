#!/bin/bash
set -Eeuo pipefail
source /project/settings.env
ARTIFACTS=/project/artifacts
BUILD_DIR=/src/out-${KV:?KV is required}
REFERENCE=/src/mu300-kernel.tar.gz

select_kernel_hash() {
    case "$KV" in
        6.18.54) printf '%s' "$KERNEL_618_SHA256" ;;
        7.2.8) printf '%s' "$KERNEL_72_SHA256" ;;
        *) echo "Unsupported kernel version: $KV" >&2; return 1 ;;
    esac
}

fetch_verified() {
    local url=$1 destination=$2 expected=$3
    curl --fail --location --show-error "$url" --output "$destination"
    printf '%s  %s\n' "$expected" "$destination" | sha256sum --check --strict -
}

prepare_sources() {
    [ "$(uname -m)" = aarch64 ]
    [ "$(git -c safe.directory=/source -C /source rev-parse HEAD)" = "$UPSTREAM_COMMIT" ]
    mkdir -p "$ARTIFACTS/logs"
    python3 /project/scripts/wlan_rx_checksum.py apply --source-root /source \
        --module-dir /work/modules/sprd_wlan_combo --output "$ARTIFACTS/wlan-rx-source.json"
    cp /work/mu300-mainline.config "$ARTIFACTS/upstream.config"
    printf '\n# F50 dae capabilities, kept separately in the build repository\n' >> /work/mu300-mainline.config
    cat /project/config/dae.config >> /work/mu300-mainline.config
    cp /work/mu300-mainline.config "$ARTIFACTS/requested.config"
    fetch_verified "https://cdn.kernel.org/pub/linux/kernel/v${KV%%.*}.x/linux-$KV.tar.xz" \
        "/src/linux-$KV.tar.xz" "$(select_kernel_hash)"
    tar -xJf "/src/linux-$KV.tar.xz" -C /src
    fetch_verified "https://github.com/dikeckaan/mu300-linux/releases/download/$UPSTREAM_RELEASE/mu300-kernel.tar.gz" \
        "$REFERENCE" "$REFERENCE_BUNDLE_SHA256"
}

record_tools() {
    {
        printf 'Kernel: %s\nUpstream commit: %s\n' "$KV" "$UPSTREAM_COMMIT"
        date -u '+Build time: %Y-%m-%dT%H:%M:%SZ'
        gcc --version
        ld --version
        pahole --version
        dpkg-query -W gcc binutils pahole libelf-dev
    } > "$ARTIFACTS/toolchain.txt"
    cp /project/settings.env "$ARTIFACTS/inputs.env"
}

compile_all() {
    export KBUILD_BUILD_USER=github-actions KBUILD_BUILD_HOST=f50-daede-kernel
    export KBUILD_BUILD_VERSION=1
    export SOURCE_DATE_EPOCH
    SOURCE_DATE_EPOCH=$(git -c safe.directory=/source -C /source show -s --format=%ct HEAD)
    export KBUILD_BUILD_TIMESTAMP
    KBUILD_BUILD_TIMESTAMP=$(date -u -d "@$SOURCE_DATE_EPOCH" '+%a %b %d %T UTC %Y')
    bash /work/build.sh 2>&1 | tee "$ARTIFACTS/logs/kernel-command.log"
    bash /work/build-modules.sh 2>&1 | tee "$ARTIFACTS/logs/vendor-command.log"
    find /work/out/modules -name '*.ko' -exec strip --strip-debug {} +
    python3 /project/scripts/validate_kernel.py --build-dir "$BUILD_DIR" \
        --module-dir /work/out/modules --config-extra /project/config/dae.config \
        --kernel-version "$KV" --output "$ARTIFACTS/kernel-validation.json"
    python3 /project/scripts/validate_wlan_rx.py \
        --module /work/out/modules/sprd_wlan_combo.ko --kernel "$BUILD_DIR/vmlinux" \
        --compiled-source /src/mod-build/sprd_wlan_combo/sc2355/rx.c \
        --source-report "$ARTIFACTS/wlan-rx-source.json" --output "$ARTIFACTS/wlan-rx-validation.json"
}

package_outputs() {
    bash /source/upstream/make-bundle.sh "$ARTIFACTS/mu300-kernel-$KV-btf.tar.gz" "$REFERENCE"
    cp "$BUILD_DIR/.config" "$ARTIFACTS/kernel.config"
    cp "$BUILD_DIR/Module.symvers" "$ARTIFACTS/Module.symvers"
    cp "$BUILD_DIR/include/config/kernel.release" "$ARTIFACTS/kernel.release"
    xz -T0 -c "$BUILD_DIR/vmlinux" > "$ARTIFACTS/vmlinux.xz"
    cd "$ARTIFACTS"
    sha256sum ./*.tar.gz ./vmlinux.xz ./vmlinux.btf ./kernel.config \
        ./kernel-validation.json ./Module.symvers ./kernel.release \
        ./wlan-rx-source.json ./wlan-rx-validation.json ./wlan-rx-patched.c \
        ./wlan-rx-helper.disasm ./wlan-skb-layout.txt \
        ./wlan_combo-rx-software-checksum.patch > SHA256SUMS
}

prepare_sources
record_tools
compile_all
package_outputs
