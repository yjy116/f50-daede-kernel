#!/bin/sh
# Restore only into an empty private test directory, never into the live root.
set -eu
umask 077
snapshot=/root/f50-snapshots/baseline-20261011
restored=/root/f50-snapshots/restore-check-20261011
test ! -e "$restored"
(cd "$snapshot" && sha256sum -c SHA256SUMS) > /root/f50-snapshots/final-snapshot-check.log
mkdir "$restored"
tar -xzpf "$snapshot/settings.tar.gz" -C "$restored"
tar -xzpf "$snapshot/runtime.tar.gz" -C "$restored"
(cd "$restored" && sha256sum -c "$snapshot/files.sha256") > /root/f50-snapshots/restore-files-check.log
while IFS="$(printf '\t')" read -r path mode uid gid; do
    actual=$(/opt/mu300/bin/busybox stat -c '%a:%u:%g' "$restored/$path")
    test "$actual" = "$mode:$uid:$gid"
done < /root/f50-snapshots/restore-metadata.tsv
tail -n +2 "$snapshot/links.tsv" |
while IFS="$(printf '\t')" read -r path target; do
    test -L "$restored/$path"
    test "$(readlink "$restored/$path")" = "$target"
done
printf 'LINUX_ISOLATED_RESTORE_CONTENT_MODE_OWNER_LINKS_PASS\n'
/etc/init.d/honk running
printf 'HONK_STILL_RUNNING\n'
