#!/bin/sh
# Explicit upgrade after the separate preflight and external backup verification.
. /root/f50-v18-20261011/deploy-common.sh
cd "$stage"
test "$(cat /etc/mu300/image-version)" = v2026.10.17
test ! -e applied.ok
sha256sum -c backups.sha256
sha256sum -c targets-before.sha256
verify_preserved
apk_local add "ucode-mod-socket=$socket_version" > apk-install.txt 2>&1
cat apk-install.txt
apk_local info --exists "ucode-mod-socket=$socket_version"
apk_local info -v | sort > packages-after.txt
{ cat packages-before.txt; printf '%s\n' "ucode-mod-socket-$socket_version"; } |
    sort > packages-expected.txt
cmp packages-after.txt packages-expected.txt
ucode -e 'import * as socket from "socket"; if (type(socket.create) != "function") die("missing socket.create"); print("SOCKET_IMPORT_PASS\n");'
tar -tzf v18-userspace-payload.tar.gz > target.paths
while IFS= read -r path; do
    path=${path#./}
    [ "$path" != etc/mu300/image-version ] || continue
    test ! -e "/$path.v18-new"
    test ! -L "/$path.v18-new"
    mkdir -p "$(dirname "/$path")"
    cp -a "$stage/payload/$path" "/$path.v18-new"
    mv -f "/$path.v18-new" "/$path"
done < target.paths
/etc/init.d/mu300-cpu enable
/etc/init.d/mu300-traffic enable
verify_links
test "$(readlink /etc/rc.d/K10mu300-traffic)" = ../init.d/mu300-traffic
verify_preserved
# Publish the release marker only after the complete code and dependency update.
cp -p payload/etc/mu300/image-version /etc/mu300/image-version.v18-new
mv /etc/mu300/image-version.v18-new /etc/mu300/image-version
(cd / && sha256sum -c "$stage/v18-target-files.sha256")
printf '%s\n' 'userspace v2026.10.18; custom kernel and Honk preserved' > applied.ok
sync
echo V18_USERSPACE_INSTALLED_REBOOT_REQUIRED
