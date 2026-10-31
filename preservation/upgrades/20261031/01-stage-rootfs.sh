#!/bin/sh
# Usage: sh 01-stage-rootfs.sh ABSOLUTE_INPUT_DIRECTORY REQUIRED_TOTAL_FREE_KIB
# REQUIRED_TOTAL_FREE_KIB is the documented full candidate/boot peak budget, not only the rootfs.
# No official apply, partition writes, service changes or reboot occur in this phase.
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$script_dir/migration-common.sh"
test "$#" -eq 2 || fail 'Expected input directory and reviewed peak-space budget in KiB'
input=$1
required_kib=$2
require_input_directory "$input"
require_old_running
verify_published_assets "$input"
case $required_kib in ''|*[!0-9]*) fail 'Space budget must be an integer KiB count' ;; esac
test "$required_kib" -ge "$F50_ROOTFS_BLOCKS_KIB" || fail 'Budget is smaller than the rootfs alone'
test ! -e "$F50_NEW" && test ! -L "$F50_NEW" || fail 'Candidate path is already occupied'
test ! -e "$F50_DISK/openwrt.old" || fail 'Previous root must first be archived and verified on the host'
free_kib=$(df -Pk "$F50_DISK" | awk 'NR==2 { print $4 }')
test "$free_kib" -ge "$required_kib" || fail 'Insufficient space for the reviewed peak budget'
umask 077
mkdir -p "$input/state"
printf 'free_kib=%s\nrequired_kib=%s\n' "$free_kib" "$required_kib" > "$input/state/stage-space.txt"
mkdir -m 755 "$F50_NEW"
tar -xzpf "$input/mu300-openwrt-luci-rootfs.tar.gz" -C "$F50_NEW"
test "$(cat "$F50_NEW/etc/mu300/image-version")" = "$F50_RELEASE"
(
    cd "$F50_NEW"
    sha256sum etc/mu300/image-version etc/mu300/image-packages \
        etc/mu300/packages.txt etc/mu300/image-manifest.gz
) > "$input/state/official-image-metadata.sha256"
test -x "$F50_NEW/opt/mu300/bin/busybox"
test -x "$F50_NEW/opt/mu300/bin/mu300-carry"
"$F50_NEW/opt/mu300/bin/busybox" true
gzip -dc "$F50_NEW/etc/mu300/image-manifest.gz" > "$input/state/published-image.manifest"
"$F50_NEW/opt/mu300/bin/mu300-carry" manifest "$F50_NEW" openwrt-luci "$F50_RELEASE" \
    > "$input/state/extracted-image.manifest"
cmp -s "$input/state/published-image.manifest" "$input/state/extracted-image.manifest" ||
    fail 'Freshly extracted root does not match the complete official manifest'
test ! -e "$F50_NEW/proc/1"
mkdir -p "$F50_NEW/dev" "$F50_NEW/tmp/lock"
for spec in null:3 zero:5 random:8 urandom:9; do
    node=${spec%:*}
    minor=${spec#*:}
    test ! -e "$F50_NEW/dev/$node" || fail 'Unexpected node in the fresh rootfs dev directory'
    mknod -m 666 "$F50_NEW/dev/$node" c 1 "$minor"
done
chroot "$F50_NEW" /opt/mu300/bin/busybox true
printf '%s\n' ROOTFS_STAGED_PLUGIN_INSTALL_AND_MIGRATION_PENDING
