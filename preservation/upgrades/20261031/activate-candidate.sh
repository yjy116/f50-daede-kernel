#!/bin/sh
# Activate only the independently validated candidate. This script never reboots.
set -eu
test "$(id -u)" = 0
disk=/mnt/mu300-disk
input=$disk/f50-official-20261031
old=$disk/openwrt
new=$disk/openwrt.new
rollback=$disk/openwrt.old
test / -ef "$old"
test ! -e "$rollback"
test ! -L "$old"
test ! -L "$new"
test "$(readlink -f "$new")" = "$new"
test "$(cat "$disk/.mu300/boot-os")" = openwrt
test "$(cat "$old/etc/mu300/default-boot")" = linux
cmp -s "$old/etc/mu300/default-boot" "$new/etc/mu300/default-boot"
test ! -e "$disk/extra/audio"
test -f "$input/state/candidate-validation-complete"
test ! -e "$new/proc/1"
test -d "$new/lib/modules/7.2.9-f50-bpf1"
test ! -L "$new/etc/rc.d/S99openclash"
test -L "$new/etc/rc.d/S99honk"
test "$(cat "$new/etc/mu300/adb")" = off
. "$input/scripts/migration-common.sh"
verify_image_metadata "$input"
verify_expected_packages "$input/state/expected-packages.tsv" "$input"
sha256sum -c "$input/state/candidate-critical.sha256" >/dev/null
sha256sum -c "$input/state/source-critical.sha256" >/dev/null
# Hold the official writer lock continuously across both root renames and the boot
# write. Source the verified updater unchanged, then use its exact kernel CLI flow
# in this same process so there is no child-process lock re-entry or unlocked gap.
verify_published_assets "$input"
cmp -s "$input/mu300-update" "$new/opt/mu300/bin/mu300-update"
export MU300_RELEASE=v2026.10.30.1
export MU300_KERNEL_BUNDLE=$input/mu300-kernel-7.2.tar.gz
export MU300_BIN=$disk/openwrt/opt/mu300/bin
command -v flock >/dev/null
set +u
MU300_LIB=1 . "$new/opt/mu300/bin/mu300-update"
unset MU300_LIB
lock_take
trap 'f50_exit=$?; set +e; unpack_abort; keepalive_stop; resume_data; lock_drop; exit "$f50_exit"' EXIT
trap 'exit 130' INT TERM HUP
modules_settle
source_conf
keepalive_start
# Recheck directory identities and the approved bytes after acquiring the writer lock.
test / -ef "$disk/openwrt"
test ! -e "$disk/openwrt.old"
test ! -L "$disk/openwrt.old"
test -d "$disk/openwrt.new"
test ! -L "$disk/openwrt.new"
test "$(readlink -f "$disk/openwrt.new")" = "$disk/openwrt.new"
test -f "$input/state/candidate-validation-complete"
verify_image_metadata "$input"
verify_expected_packages "$input/state/expected-packages.tsv" "$input"
sha256sum -c "$input/state/candidate-critical.sha256" >/dev/null
sha256sum -c "$input/state/source-critical.sha256" >/dev/null
test "$(linux_slot)" = b
test "$(boot_dev boot_b)" = /dev/mmcblk0p38
test "$(part_bytes /dev/mmcblk0p38)" = 67108864
printf 'validated-before-rename\n' > "$input/state/activation-state"
sync
mv "$old" "$rollback"
if ! mv "$new" "$old"; then
    mv "$rollback" "$old"
    echo 'Candidate rename failed; original path restored; boot unchanged' >&2
    exit 1
fi
printf 'root-switched-kernel-write-pending\n' > "$input/state/activation-state"
sync
# On an updater error the old root is still running. Do not reboot or pretend success:
# retain this state and inspect readback, restoring the independently saved boot image
# and root names if needed. The host owns before-boot_b.img and before-boot-policy.tar.gz.
set +e
kernel_cmd 7.2
kernel_result=$?
set -e
test "$kernel_result" = 0 || exit "$kernel_result"
printf 'kernel-command-complete-independent-readback-pending\n' > "$input/state/activation-state"
sync
echo ACTIVATION_COMPLETE_REBOOT_NOT_PERFORMED
