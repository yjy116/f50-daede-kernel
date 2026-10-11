#!/bin/sh
# Manual recovery only; never silently roll back a failed verification.
. /root/f50-v18-20261011/deploy-common.sh
cd "$stage"
sha256sum -c backups.sha256
for service in mu300-traffic mu300-cpu; do
    if [ -x "/etc/init.d/$service" ]; then
        "/etc/init.d/$service" stop
        "/etc/init.d/$service" disable
    fi
done
apk_local del ucode-mod-socket
while IFS= read -r path; do
    case "$path" in etc/*|opt/*|usr/*|www/*) ;; *) echo "Unexpected path: $path" >&2; exit 1;; esac
    test ! -d "/$path"
    rm -f "/$path"
done < added.paths
tar -xpf before.tar -C /
sha256sum -c targets-before.sha256
apk_local info -v | sort > packages-rolled-back.txt
cmp packages-before.txt packages-rolled-back.txt
verify_preserved
sync
echo V17_USERSPACE_RESTORED_REBOOT_REQUIRED
