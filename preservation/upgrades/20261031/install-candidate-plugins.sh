#!/bin/sh
# Run only in the independent candidate chroot. Mode: prepare or install.
set -eu
mode=${1:?Usage: install-candidate-plugins.sh prepare|install}
input=/f50-install-inputs
test ! -e /proc/1
test "$(cat /etc/mu300/image-version)" = v2026.10.30.1
test -d "$input/keys"

apk_input() {
    env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C IPKG_INSTROOT=/ \
        apk --preserve-env --keys-dir "$input/keys" \
        --repositories-file "$input/repositories.list" --no-network "$@"
}

prepare() {
    # Standalone custom APKs are signed; official payloads are vouched for by signed indices.
    while IFS= read -r relative; do
        test -n "$relative" || continue
        apk_input verify "$input/$relative"
    done < "$input/custom-apks.txt"
    apk_input update
    apk_input del --simulate dnsmasq
    apk_input del dnsmasq
}

case "$mode" in
    prepare) prepare ;;
    install) test ! -e "$input/installation-complete" ;;
    *) echo 'Unsupported install phase' >&2; exit 2 ;;
esac

set --
while IFS= read -r relative; do
    test -n "$relative" || continue
    set -- "$@" "$input/$relative"
done < "$input/custom-apks.txt"
while IFS= read -r package; do
    test -n "$package" || continue
    set -- "$@" "$package"
done < "$input/official-requests.txt"

if [ "$mode" = prepare ]; then
    apk_input add --simulate "$@"
    echo CANDIDATE_PLUGIN_SIMULATION_COMPLETE
    exit 0
fi
apk_input add "$@"
awk '/^P:/ {p=substr($0,3)} /^V:/ {print p "\t" substr($0,3)}' \
    /lib/apk/db/installed | sort > "$input/installed-packages.tsv"
touch "$input/installation-complete"
echo CANDIDATE_PLUGIN_INSTALL_COMPLETE
