#!/bin/sh
set -eu
stage=/root/f50-v18-20261011
socket_version='2026.01.16~85922056-r2'
apk_local() {
    apk --keys-dir /etc/apk/keys --repositories-file "$stage/repositories.list" \
        --cache-dir "$stage/cache" --no-network "$@"
}
verify_links() {
    tail -n +2 "$stage/v18-target-links.tsv" |
    while IFS="$(printf '\t')" read -r path mode uid gid target; do
        test -L "/$path"
        test "$(readlink "/$path")" = "$target"
    done
}
verify_preserved() {
    sha256sum -c "$stage/preserved.sha256" > "$stage/preserved-check.log"
    test "$(uname -r)" = 7.2.9-f50-bpf1
}
