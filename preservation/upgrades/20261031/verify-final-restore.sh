#!/bin/sh
# Test the finalized snapshot only inside a new, private Linux directory.
set -eu
umask 077
phase=${1:?Usage: verify-final-restore.sh nosim|validated}
case "$phase" in nosim|validated) ;; *) exit 2 ;; esac
snapshot=/root/f50-snapshots/official-$phase-20261031
restored=/root/f50-snapshots/restore-check-official-$phase-20261031
evidence=/mnt/mu300-disk/f50-official-20261031/state
test ! -e "$restored"
test "$(readlink -f "$snapshot")" = "$snapshot"
test ! -e "$snapshot/INCOMPLETE"
(cd "$snapshot" && sha256sum -c SHA256SUMS) > "$evidence/final-snapshot-check.log"
mkdir "$restored"
tar -xzpf "$snapshot/settings.tar.gz" -C "$restored"
tar -xzpf "$snapshot/runtime.tar.gz" -C "$restored"
(cd "$restored" && sha256sum -c "$snapshot/files.sha256") > "$evidence/restore-files-check.log"
while IFS="$(printf '\t')" read -r path mode uid gid; do
    actual=$(/opt/mu300/bin/busybox stat -c '%a:%u:%g' "$restored/$path")
    test "$actual" = "$mode:$uid:$gid"
done < "$snapshot/restore-metadata.tsv"
tail -n +2 "$snapshot/links.tsv" |
while IFS="$(printf '\t')" read -r path target; do
    test -L "$restored/$path"
    test "$(readlink "$restored/$path")" = "$target"
done
echo LINUX_ISOLATED_RESTORE_CONTENT_MODE_OWNER_LINKS_PASS
/etc/init.d/honk running
echo HONK_STILL_RUNNING
