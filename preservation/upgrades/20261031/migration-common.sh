#!/bin/sh
# Shared checks for the reviewed, independent candidate-root workflow.
# Sourced by the phase scripts; these files have not been run on the device.
set -eu
export LC_ALL=C
readonly F50_DISK=/mnt/mu300-disk
readonly F50_OLD=$F50_DISK/openwrt
readonly F50_NEW=$F50_DISK/openwrt.new
readonly F50_RELEASE=v2026.10.30.1
readonly F50_KERNEL=7.2.13
readonly F50_ROOTFS_BLOCKS_KIB=63752

fail() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

require_input_directory() {
    case $1 in /*) ;; *) fail 'Input directory must be absolute' ;; esac
    test -d "$1" || fail 'Input directory is missing'
    test ! -L "$1" || fail 'Input directory must not be a symbolic link'
    case $(readlink -f "$1") in
        "$F50_DISK/.mu300-update"|"$F50_DISK/.mu300-update/"*)
            fail 'Official boot removes .mu300-update; store caller inputs elsewhere' ;;
    esac
}

verify_published_assets() {
    (
        cd "$1"
        sha256sum -c <<'SUMS'
d3d682e9b3fc619fb22c09364a1f3da7415e0517e71ff3973e9e4287e1be275e  mu300-openwrt-luci-rootfs.tar.gz
f52f3e043ea5fc6cb58e187a7643a35053b5eda1ad7b5c9de71ae8feae9ff03a  mu300-kernel-7.2.tar.gz
cda543e8c077e92fffbea947a4662f571a5718ae9b82fba6491801674a6df12e  mu300-update
SUMS
    ) || fail 'Published asset bytes differ from reviewed release'
}

require_old_running() {
    test / -ef "$F50_OLD" || fail 'Running root is not the expected current root'
    test "$(cat "$F50_OLD/etc/mu300/image-version")" = v2026.10.18 ||
        fail 'Current userspace differs from the reviewed baseline'
    test "$(uname -r)" = 7.2.9-f50-bpf1 ||
        fail 'Current kernel differs from the reviewed baseline'
}

verify_image_metadata() {
    test "$(cat "$F50_NEW/etc/mu300/image-version")" = "$F50_RELEASE"
    (cd "$F50_NEW" && sha256sum -c "$1/state/official-image-metadata.sha256") ||
        fail 'Official image metadata changed during candidate preparation'
}

verify_expected_packages() {
    test -s "$1" || fail 'Expected package TSV is missing'
    awk -F '\t' 'NF != 2 || $1 == "" || $2 == "" { bad=1 } END { exit bad }' "$1" ||
        fail 'Expected package TSV must contain exactly name<TAB>version, without a header'
    sort "$1" > "$2/state/expected-packages.sorted"
    awk '/^P:/ {p=substr($0,3)} /^V:/ {print p "\t" substr($0,3)}' \
        "$F50_NEW/lib/apk/db/installed" | sort > "$2/state/actual-packages.sorted"
    if ! cmp -s "$2/state/expected-packages.sorted" "$2/state/actual-packages.sorted"; then
        diff -u "$2/state/expected-packages.sorted" "$2/state/actual-packages.sorted" >&2 || :
        fail 'Candidate APK name/version set does not match the complete plan'
    fi
}

require_quiesced_honk() {
    if /etc/init.d/honk running; then
        fail 'Honk is still writing its database; the controller must stop it for carry'
    fi
    if pidof honk-core >/dev/null 2>&1; then
        fail 'A honk-core process remains; do not copy its live database'
    fi
}

