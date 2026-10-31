#!/bin/sh
# Preserve service choices and bind the existing capture profile to the official kernel.
set -eu
disk=/mnt/mu300-disk
old=$disk/openwrt
new=$disk/openwrt.new
input=$disk/f50-official-20261031
test / -ef "$old"
test ! -e "$new/proc/1"
test "$(cat "$new/etc/mu300/image-version")" = v2026.10.30.1

preserve_services() {
    for init in "$old"/etc/init.d/*; do
        name=${init##*/}
        test -x "$new/etc/init.d/$name" || continue
        enabled=0
        for link in "$old"/etc/rc.d/S??"$name"; do
            test ! -L "$link" || enabled=1
        done
        for link in "$new"/etc/rc.d/[SK]??"$name"; do
            test ! -L "$link" || rm "$link"
        done
        if test "$enabled" = 1; then
            chroot "$new" /usr/bin/env IPKG_INSTROOT=/ \
                /bin/sh /etc/rc.common "/etc/init.d/$name" enable
        fi
        printf '%s\t%s\n' "$name" "$enabled"
    done > "$input/state/preserved-service-choices.tsv"
}

preserve_services
test ! -L "$new/etc/rc.d/S99openclash"
test -L "$new/etc/rc.d/S99honk"
# This installation previously had no ADB service. The new official default would
# expose unauthenticated root ADB; its documented off setting preserves that state.
printf 'off\n' > "$new/etc/mu300/adb"
chmod 600 "$new/etc/mu300/adb"
profile=$new/etc/mu300/f50-profile
sed 's@lib/modules/7.2.9-f50-bpf1@lib/modules/7.2.13@' \
    "$profile/preserve-paths.txt" > "$input/state/preserve-paths.new"
cat "$input/state/preserve-paths.new" > "$profile/preserve-paths.txt"
printf '%s  %s\n' f52f3e043ea5fc6cb58e187a7643a35053b5eda1ad7b5c9de71ae8feae9ff03a \
    "$input/mu300-kernel-7.2.tar.gz" > "$profile/kernel-bundle.sha256"
sync
printf '%s\n' SERVICE_CHOICES_AND_OFFICIAL_KERNEL_CAPTURE_PROFILE_PREPARED
