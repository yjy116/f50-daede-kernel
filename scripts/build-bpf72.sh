#!/bin/bash
set -Eeuo pipefail
source /project/settings-bpf72.env
export KV
ARTIFACTS=/project/artifacts
BUILD_DIR=/src/out-$KV
HELPERS=/src/mu300-kernel.tar.gz
REFERENCE=/src/mu300-kernel-7.2.tar.gz
BUNDLE=$ARTIFACTS/mu300-kernel-$KV$LOCAL_VERSION.tar.gz

fetch_verified() {
    local url=$1 destination=$2 expected=$3
    curl --fail --location --show-error "$url" --output "$destination"
    printf '%s  %s\n' "$expected" "$destination" | sha256sum --check --strict -
}

prepare_sources() {
    [ "$(uname -m)" = aarch64 ]
    [ "$(git -c safe.directory=/source -C /source rev-parse HEAD)" = "$UPSTREAM_COMMIT" ]
    mkdir -p "$ARTIFACTS/logs"
    cp /work/mu300-mainline.config "$ARTIFACTS/upstream.config"
    python3 /project/scripts/merge_kernel_config.py --base /work/mu300-mainline.config \
        --fragment /project/config/bpf72.config --output /work/mu300-mainline.config
    cp /work/mu300-mainline.config "$ARTIFACTS/requested.config"
    fetch_verified "https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-$KV.tar.xz" \
        "/src/linux-$KV.tar.xz" "$KERNEL_SHA256"
    tar -xJf "/src/linux-$KV.tar.xz" -C /src
    local release="https://github.com/dikeckaan/mu300-linux/releases/download/$UPSTREAM_RELEASE"
    fetch_verified "$release/mu300-kernel.tar.gz" "$HELPERS" "$HELPER_BUNDLE_SHA256"
    fetch_verified "$release/mu300-kernel-7.2.tar.gz" "$REFERENCE" "$REFERENCE_BUNDLE_SHA256"
    python3 /project/scripts/bpf72_bundle.py prepare-reference --bundle "$REFERENCE" \
        --output "$ARTIFACTS/reference-modules.json"
}

record_tools() {
    {
        printf 'Kernel: %s%s\nUpstream commit: %s\n' "$KV" "$LOCAL_VERSION" "$UPSTREAM_COMMIT"
        date -u '+Build time: %Y-%m-%dT%H:%M:%SZ'
        gcc --version
        ld --version
        pahole --version
        dpkg-query -W gcc binutils pahole libelf-dev
    } > "$ARTIFACTS/toolchain.txt"
    cp /project/settings-bpf72.env "$ARTIFACTS/inputs.env"
    cp /project/config/bpf72.config "$ARTIFACTS/bpf72.config"
}

compile_probe() {
    gcc -static -O2 -Wall -Wextra -Werror -std=c11 \
        /project/tools/bpf72-probe.c -o "$ARTIFACTS/bpf72-probe"
    readelf -h "$ARTIFACTS/bpf72-probe" > "$ARTIFACTS/probe-elf-header.txt"
    readelf -l "$ARTIFACTS/bpf72-probe" > "$ARTIFACTS/probe-program-headers.txt"
    ! grep -q INTERP "$ARTIFACTS/probe-program-headers.txt"
    cp /project/tools/bpf72-probe.c "$ARTIFACTS/bpf72-probe.c"
}

compile_all() {
    export KBUILD_BUILD_USER=github-actions KBUILD_BUILD_HOST=f50-bpf72
    export KBUILD_BUILD_VERSION=1 SOURCE_DATE_EPOCH KBUILD_BUILD_TIMESTAMP
    SOURCE_DATE_EPOCH=$(git -c safe.directory=/source -C /source show -s --format=%ct HEAD)
    KBUILD_BUILD_TIMESTAMP=$(date -u -d "@$SOURCE_DATE_EPOCH" '+%a %b %d %T UTC %Y')
    bash /work/build.sh 2>&1 | tee "$ARTIFACTS/logs/kernel-command.log"
    bash /work/build-modules.sh 2>&1 | tee "$ARTIFACTS/logs/vendor-command.log"
    find /work/out/modules -name '*.ko' -exec strip --strip-debug {} +
    python3 /project/scripts/validate_kernel.py --build-dir "$BUILD_DIR" \
        --module-dir /work/out/modules --config-extra /project/config/bpf72.config \
        --kernel-version "$KV" --local-version="$LOCAL_VERSION" \
        --module-manifest "$ARTIFACTS/reference-modules.json" \
        --output "$ARTIFACTS/kernel-validation.json"
    grep -w 'bpf_int_jit_compile' "$BUILD_DIR/System.map" > "$ARTIFACTS/jit-symbol.txt"
}

package_outputs() {
    bash /source/upstream/make-bundle.sh "$BUNDLE" "$HELPERS"
    python3 /project/scripts/bpf72_bundle.py verify --bundle "$BUNDLE" \
        --reference "$ARTIFACTS/reference-modules.json" --module-dir /work/out/modules \
        --kernel-release "$KV$LOCAL_VERSION" --output "$ARTIFACTS/bundle-validation.json"
    cp "$BUILD_DIR/.config" "$ARTIFACTS/kernel.config"
    cp "$BUILD_DIR/Module.symvers" "$ARTIFACTS/Module.symvers"
    cp "$BUILD_DIR/modules.in-tree" "$ARTIFACTS/modules.in-tree"
    cp "$BUILD_DIR/include/config/kernel.release" "$ARTIFACTS/kernel.release"
    xz -T0 -c "$BUILD_DIR/vmlinux" > "$ARTIFACTS/vmlinux.xz"
    cd "$ARTIFACTS"
    find . -maxdepth 1 -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
}

prepare_sources
record_tools
compile_probe
compile_all
package_outputs
