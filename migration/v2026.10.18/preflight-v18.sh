#!/bin/sh
# Prepare and verify the entire delta before changing any live application file.
. /root/f50-v18-20261011/deploy-common.sh
cd "$stage"
test "$(cat /etc/mu300/image-version)" = v2026.10.17
test ! -e before.tar
test ! -e payload
test ! -e /etc/rc.d/K10mu300-traffic
test ! -e /etc/mu300/cpu.conf
test ! -e /etc/mu300/traffic.conf
test -z "$(uci changes)"
printf '%s\n' \
 '88ccd2dc8ef14dfa6133e78eb79252418043515c3a0b12dabc3c25a6e1122dc5  v18-userspace-payload.tar.gz' \
 'e72f7d7f5017e3f300f006da37027f19cb2157178b4e88f851afb2e48e1cc35e  socket-package/ucode-mod-socket-2026.01.16~85922056-r2.apk' \
 'bd10218cc2d3c35b8957f55d60d5cedf6bd392aec7deafc5634c4acb4ffcd779  socket-package/packages.adb' | sha256sum -c -
mkdir payload cache
tar -xzpf v18-userspace-payload.tar.gz -C payload
(cd payload && sha256sum -c ../v18-target-files.sha256)
awk '$1 == "ABSENT" {print $2}' live-targets-before.txt > added.paths
awk '$1 != "ABSENT" {print substr($2,2)}' live-targets-before.txt > existing.paths
awk '$1 != "ABSENT"' live-targets-before.txt > targets-before.sha256
sha256sum -c targets-before.sha256
while IFS= read -r path; do
    test ! -e "/$path"
    test ! -L "/$path"
done < added.paths
tar -cpf before.tar -C / -T "$stage/existing.paths"
tar -cpf apk-before.tar -C / etc/apk/world lib/apk/db
sha256sum before.tar apk-before.tar > backups.sha256
find /etc/config /etc/honk/config.d /lib/modules/7.2.9-f50-bpf1 \
    /mnt/mu300-disk/boot -type f -exec sha256sum '{}' + > preserved.sha256
sha256sum /dev/mmcblk0p38 /usr/bin/honk-core /etc/init.d/honk \
    /etc/init.d/mu300-hw /etc/honk/config.dae /etc/passwd /etc/shadow \
    /etc/uhttpd.crt /etc/uhttpd.key /opt/mu300/bin/mobile-data \
    /usr/share/rpcd/acl.d/luci-f50-thermal.json \
    /www/luci-static/resources/view/status/include/15_f50_thermal.js \
    /usr/share/luci/menu.d/luci-app-doona.json \
    /www/luci-static/resources/view/services/doona.js >> preserved.sha256
printf '%s\n' "$stage/socket-package/packages.adb" > repositories.list
apk_local verify "$stage/socket-package/packages.adb"
apk_local update
apk_local info -v | sort > packages-before.txt
apk_local add --simulate "ucode-mod-socket=$socket_version" > apk-simulation.txt
cat apk-simulation.txt
verify_preserved
sync
cat backups.sha256
echo V18_PREFLIGHT_READY
