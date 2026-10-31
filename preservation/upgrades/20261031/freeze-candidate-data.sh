#!/bin/sh
# Copy the final closed proxy database and retain runtime-updated routing data.
set -eu
disk=/mnt/mu300-disk
old=$disk/openwrt
new=$disk/openwrt.new
input=$disk/f50-official-20261031
test / -ef "$old"
test ! -e "$new/proc/1"
test -z "$(uci changes)"
/etc/init.d/honk stop
/opt/mu300/bin/busybox timeout 30 sh -c \
    'while pidof honk-core >/dev/null 2>&1; do sleep 1; done'
if /etc/init.d/honk running; then
    echo 'Honk failed to stop' >&2
    exit 1
fi
for suffix in -wal -shm; do
    path=etc/honk/data/state/honk.db$suffix
    if test ! -e "$old/$path"; then rm -f "$new/$path"; fi
done
cp -a "$old/etc/honk/." "$new/etc/honk/"
for path in etc/homeproxy/resources/china_ip6.ver etc/homeproxy/resources/china_list.txt \
    etc/homeproxy/resources/china_ip6.txt etc/homeproxy/resources/china_ip4.txt \
    etc/homeproxy/resources/china_ip4.ver etc/homeproxy/resources/gfw_list.txt \
    etc/homeproxy/resources/china_list.ver etc/homeproxy/resources/gfw_list.ver \
    etc/openclash/china_ip6_route.ipset etc/openclash/china_ip_route.ipset; do
    test -f "$old/$path"
    cp -p "$old/$path" "$new/$path"
done
# The same-version package supplies these hooks as 0644; its previously completed
# initializer had made them executable. Retain the already-used 0755 state.
chmod 755 "$new/etc/openclash/custom/openclash_custom_firewall_rules.sh" \
    "$new/etc/openclash/custom/openclash_custom_overwrite.sh"
sync
printf '%s\n' HONK_CLOSED_DATA_COPIED_OLD_SERVICE_INTENTIONALLY_STOPPED_UNTIL_SWITCH
