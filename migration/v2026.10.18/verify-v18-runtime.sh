#!/bin/sh
# Read-only runtime checks; only this invocation's evidence directory is written.
set -eu
umask 077
VERIFY_TIMEOUT=60
READ_TIMEOUT=10
BUSYBOX=/opt/mu300/bin/busybox
BOOT_DEVICE=/dev/mmcblk0p38
BOOT_PARTITION_BYTES=67108864
BOOT_BODY_BYTES=40102144
BOOT_FOOTER_BYTES=64
BOOT_READ_BLOCK_BYTES=1048576
BOOT_SECTOR_BYTES=512
EXPECTED_PRESERVED_FILES=436
if [ "${F50_V18_VERIFY_CHILD:-0}" != 1 ]; then
    exec env F50_V18_VERIFY_CHILD=1 "$BUSYBOX" timeout "$VERIFY_TIMEOUT" sh "$0" "$@"
fi
stage=$(cd "${1:?Stage directory required}" && pwd -P)
preserved=${2:?Absolute preserved SHA256 manifest required}
case "$preserved" in /*) ;; *) echo 'FAIL: preserved manifest must be absolute' >&2; exit 2 ;; esac
evidence="$stage/runtime-$(date +%Y%m%dT%H%M%S)-$$"
mkdir "$evidence"
trap 'status=$?; [ "$status" -eq 0 ] || printf "V18_RUNTIME_VERIFY_FAILED exit=%s evidence=%s\n" "$status" "$evidence" >&2' 0

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
same() { [ "$1" = "$2" ] || fail "$3"; }
read_cmd() { "$BUSYBOX" timeout "$READ_TIMEOUT" "$@"; }
pass() { printf 'PASS: %s\n' "$1"; }

verify_targets() {
    "$BUSYBOX" --list > "$evidence/busybox-applets.txt"
    grep -Fxq stat "$evidence/busybox-applets.txt" || fail 'Bundled BusyBox has no stat applet'
    test -s "$stage/v18-target-files.sha256"
    test -s "$stage/userspace-migration-manifest.json"
    jq -er '.[] | select(.action == "apply_upstream_file" or .action == "replace_image_metadata") |
        [.path, .mode, .uid, .gid, .type, .link_target] | @tsv' \
        "$stage/userspace-migration-manifest.json" > "$evidence/target-metadata.tsv"
    same "$(wc -l < "$evidence/target-metadata.tsv" | tr -d ' ')" 38 'Target count must be 38'
    (cd / && sha256sum -c "$stage/v18-target-files.sha256") > "$evidence/target-sha256.log"
    while IFS="$(printf '\t')" read -r path mode uid gid kind link; do
        actual=$("$BUSYBOX" stat -c '%a:%u:%g' "/$path")
        same "$actual" "${mode#0o}:$uid:$gid" "Wrong mode/owner: $path"
        if [ "$kind" = symlink ]; then
            test -L "/$path" || fail "Not a symlink: $path"
            same "$(readlink "/$path")" "$link" "Wrong link target: $path"
        else
            test -f "/$path" && test ! -L "/$path" || fail "Not a regular file: $path"
        fi
    done < "$evidence/target-metadata.tsv"
    pass 'All 38 upstream targets: content, type, ownership, permissions and symlinks'
}

verify_boot_regions() {
    same "$(cat /sys/class/block/mmcblk0p38/size)" \
        "$((BOOT_PARTITION_BYTES / BOOT_SECTOR_BYTES))" 'Boot partition size changed'
    blocks=$(((BOOT_BODY_BYTES + BOOT_READ_BLOCK_BYTES - 1) / BOOT_READ_BLOCK_BYTES))
    # head may close the pipe before the last dd block; exact size and SHA verify the entire body.
    dd if="$BOOT_DEVICE" bs="$BOOT_READ_BLOCK_BYTES" count="$blocks" 2> "$evidence/boot-body-dd.log" |
        "$BUSYBOX" head -c "$BOOT_BODY_BYTES" > "$evidence/boot-body.readback"
    dd if="$BOOT_DEVICE" bs="$BOOT_READ_BLOCK_BYTES" \
        skip="$((BOOT_PARTITION_BYTES / BOOT_READ_BLOCK_BYTES - 1))" count=1 \
        2> "$evidence/boot-footer-dd.log" |
        "$BUSYBOX" tail -c "$BOOT_FOOTER_BYTES" > "$evidence/boot-footer.readback"
    same "$(wc -c < "$evidence/boot-body.readback" | tr -d ' ')" "$BOOT_BODY_BYTES" 'Boot body short read'
    same "$(wc -c < "$evidence/boot-footer.readback" | tr -d ' ')" "$BOOT_FOOTER_BYTES" 'Boot footer short read'
    printf '%s  %s\n' \
        29a3a5181726696709fb3419d5886c4d6e20447bb39e22998b906f428b190bf2 "$evidence/boot-body.readback" \
        193f27a5e4ab975f56b7cb1f098750e561e6e28a057588af73423258a7d53a14 "$evidence/boot-footer.readback" \
        > "$evidence/boot-regions.sha256"
    sha256sum -c "$evidence/boot-regions.sha256" > "$evidence/boot-regions-check.log"
    printf '%s\n' 'Original preserved.sha256 retained unchanged.' \
        'Boot image [0,40102144) and partition final 64 bytes match original pinned SHA256.' \
        'Whole-partition SHA is not a cross-boot invariant: boot/init writes logs at 48-56 MiB.' \
        > "$evidence/boot-verification-scope.txt"
    pass 'Original boot body and AVB footer hashes preserved; mutable log area is documented'
}

verify_preserved_files() {
    test -s "$preserved"
    cp "$preserved" "$evidence/preserved-original.sha256"
    awk -v boot="$BOOT_DEVICE" '$2 == boot' "$preserved" > "$evidence/boot-whole-before.sha256"
    awk -v boot="$BOOT_DEVICE" '$2 != boot' "$preserved" > "$evidence/preserved-files.sha256"
    same "$(wc -l < "$evidence/boot-whole-before.sha256" | tr -d ' ')" 1 'Expected one boot partition entry'
    same "$(wc -l < "$evidence/preserved-files.sha256" | tr -d ' ')" "$EXPECTED_PRESERVED_FILES" \
        'Preserved file count changed'
    (cd / && sha256sum -c "$evidence/preserved-files.sha256") > "$evidence/preserved-sha256.log"
    verify_boot_regions
}

verify_preserved_kernel_honk() {
    verify_preserved_files
    same "$(cat /etc/mu300/image-version)" v2026.10.18 'Wrong image version'
    same "$(uname -r)" 7.2.9-f50-bpf1 'Custom kernel changed'
    same "$(cat /proc/sys/net/core/bpf_jit_enable)" 1 'BPF JIT disabled'
    test -s /sys/kernel/btf/vmlinux
    printf '%s  %s\n' \
        a4e83dd87ad93d13aa24f9ffb90d2ce10377fd5e04138156d48d5d5bf0579110 /sys/kernel/btf/vmlinux \
        2fe7ac7d6aca96f01881c8fc67f27da69557745cc6546926392004fb41ca1c45 /usr/bin/honk-core \
        | sha256sum -c - > "$evidence/kernel-honk-sha256.log"
    gzip -dc /proc/config.gz > "$evidence/running-kernel.config"
    printf '%s  %s\n' b1af9651102bbb57ae20b279b163cf5cb9338dd8640e2501794ec763912e3c80 \
        "$evidence/running-kernel.config" | sha256sum -c - >> "$evidence/kernel-honk-sha256.log"
    read_cmd /usr/bin/honk-core --version > "$evidence/honk-version.txt"
    grep -Fq debug.2026.10.9.native-api.2-f50-sipa1 "$evidence/honk-version.txt"
    pass 'v18 userspace with original custom BPF kernel, SIPA Honk and preserved files'
}

verify_socket() {
    apk info --exists 'ucode-mod-socket=2026.01.16~85922056-r2'
    printf '%s  %s\n' \
        328ad54fee1c7c76e5b9c0e68c3b30f3a70eae877d4fe349c14c3fda4ed011ee /lib/apk/packages/ucode-mod-socket.list \
        3514d4c12693a5b0715ade13f62a5bb84dcd1f963b5cf635238fbf5764e8368d /usr/lib/ucode/socket.so \
        | sha256sum -c - > "$evidence/socket-sha256.log"
    read_cmd ucode -e 'import * as socket from "socket"; print(type(socket.create), "\n");' \
        > "$evidence/socket-import.txt"
    same "$(cat "$evidence/socket-import.txt")" function 'socket module did not export create()'
    pass 'Exact socket package and working ucode module import'
}

verify_readonly_settings() {
    test ! -e /etc/mu300/cpu.conf && test ! -L /etc/mu300/cpu.conf \
        || fail 'CPU profile is configured; expected untouched default'
    test ! -e /run/mu300/cpu-ceiling && test ! -L /run/mu300/cpu-ceiling \
        || fail 'CPU ceiling exists; review whether a profile was applied'
    read_cmd ubus call mu300dash cpu_get '{}' > "$evidence/cpu-status.json"
    jq -e '.ok == 1 and .profile == "balanced" and (.policies | length > 0)' \
        "$evidence/cpu-status.json" > /dev/null
    read_cmd ubus call mu300dash traffic_get '{}' > "$evidence/traffic-status.json"
    jq -e '.device == "sipa_eth0" and .available == 1 and .cap.bytes == 0 and
        .cap.cut == 0 and .cap.cut_active == 0' "$evidence/traffic-status.json" > /dev/null
    # Only getters were called. CPU min/max may still vary due to the existing thermal guard.
    pass 'CPU has no configured profile; traffic cap and automatic cutoff are disabled'
}

verify_services() {
    /etc/init.d/mu300-cpu enabled
    /etc/init.d/mu300-traffic enabled
    /etc/init.d/mu300-post enabled
    /etc/init.d/honk enabled
    same "$(readlink /etc/rc.d/K10mu300-traffic)" ../init.d/mu300-traffic 'Missing traffic shutdown link'
    read_cmd ubus call service list '{"name":"mu300-traffic"}' > "$evidence/service-traffic.json"
    jq -e '."mu300-traffic".instances | length > 0 and all(.[]; .running == true)' \
        "$evidence/service-traffic.json" > /dev/null
    read_cmd ubus call service list '{"name":"mu300-post"}' > "$evidence/service-post.json"
    jq -e '."mu300-post".instances | .ledevents.running == true and
        .cellwatch.running == true and .thermalguard.running == true' \
        "$evidence/service-post.json" > /dev/null
    read_cmd ubus call service list '{"name":"honk"}' > "$evidence/service-honk.json"
    jq -e '.honk.instances | length > 0 and any(.[]; .running == true)' \
        "$evidence/service-honk.json" > /dev/null
    # mu300-cpu is a one-shot init script, so a persistent procd instance is not expected.
    pass 'New services enabled, traffic/LED/cellular/thermal/Honk processes running'
}

verify_rpc_menu() {
    read_cmd ubus call mu300rates netdev '{}' > "$evidence/mu300rates.json"
    jq -e '.data | type == "string" and contains("Inter-") and contains("sipa_eth0:")' \
        "$evidence/mu300rates.json" > /dev/null
    jq -e '.["admin/system/cpu"].action.path == "mu300/cpu" and
        .["admin/modem/traffic"].action.path == "mu300/traffic" and
        .["admin/modem/sms-forward"].action.path == "mu300/forward"' \
        /usr/share/luci/menu.d/luci-app-mu300.json > /dev/null
    jq -e '.["luci-app-mu300"].read.ubus.mu300rates | index("netdev") != null' \
        /usr/share/rpcd/acl.d/luci-app-mu300.json > /dev/null
    jq -e 'type == "object" and length > 0' /usr/share/rpcd/acl.d/luci-f50-thermal.json > /dev/null
    jq -e 'type == "object" and length > 0' /usr/share/luci/menu.d/luci-app-doona.json > /dev/null
    pass 'mu300rates.netdev responds and new menus/ACL JSON are valid'
}

fetch_http() {
    code=$(curl --noproxy '*' -fsSL --connect-timeout 3 --max-time "$READ_TIMEOUT" \
        --output "$2" --write-out '%{http_code}' "$1")
    same "$code" 200 "HTTP not successful: $1"
    test -s "$2" || fail "Empty HTTP body: $1"
}

verify_http() {
    code=$(curl --noproxy '*' -sS --connect-timeout 3 --max-time "$READ_TIMEOUT" \
        -D "$evidence/luci-login.headers" -o "$evidence/luci-login.html" \
        -w '%{http_code}' http://127.0.0.1/cgi-bin/luci/)
    same "$code" 403 'Unauthenticated LuCI must require login'
    grep -Eqi '^x-luci-login-required: yes' "$evidence/luci-login.headers"
    grep -q 'name="luci_username"' "$evidence/luci-login.html"
    grep -q 'name="luci_password"' "$evidence/luci-login.html"
    fetch_http http://192.168.77.1:9527/ui/ "$evidence/doona.html"
    grep -Eqi '<html|<!doctype' "$evidence/doona.html"
    for view in cpu traffic forward; do
        fetch_http "http://127.0.0.1/luci-static/resources/view/mu300/$view.js" "$evidence/$view.js"
        cmp "$evidence/$view.js" "/www/luci-static/resources/view/mu300/$view.js"
    done
    pass 'LuCI requires login with its real form; Doona UI and three new views return HTTP 200'
}

printf 'Evidence: %s\n' "$evidence"
verify_targets
verify_preserved_kernel_honk
verify_socket
verify_readonly_settings
verify_services
verify_rpc_menu
verify_http
printf 'V18_USERSPACE_RUNTIME_PASS\n'
