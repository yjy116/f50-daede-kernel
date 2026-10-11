#!/bin/sh
# Capture the running configuration; does not upgrade or reboot the device.
set -eu
umask 077
profile=/etc/mu300/f50-profile
snapshot=${1:?Usage: capture.sh ABSOLUTE_NEW_SNAPSHOT_DIRECTORY}
case "$snapshot" in /*) ;; *) echo 'Snapshot path must be absolute' >&2; exit 1 ;; esac
test ! -e "$snapshot"
mkdir -p "$snapshot"
touch "$snapshot/INCOMPLETE"
resume_honk=

resume_service() {
    if [ -n "$resume_honk" ]; then
        if ! /etc/init.d/honk start; then
            echo 'ERROR: Honk start request failed' >&2
            return 1
        fi
        if ! /opt/mu300/bin/busybox timeout "${F50_HONK_START_TIMEOUT_SECONDS:-30}" \
            sh -c 'while ! /etc/init.d/honk running; do sleep 1; done'; then
            echo 'ERROR: Honk did not reach running state' >&2
            return 1
        fi
        resume_honk=
        echo 'HONK_RUNNING_RESTORED'
    fi
}

finish() {
    result=$?
    trap - EXIT HUP INT TERM
    if ! resume_service; then
        echo 'ERROR: Honk restart failed; snapshot remains incomplete' >&2
        result=1
    fi
    exit "$result"
}
trap finish EXIT
trap 'exit 1' HUP INT TERM

record_inventory() {
    date -u '+%Y-%m-%dT%H:%M:%SZ' > "$snapshot/captured-at.txt"
    uname -r > "$snapshot/kernel.txt"
    cat /etc/mu300/image-version > "$snapshot/image-version.txt"
    /usr/bin/honk-core --version > "$snapshot/honk-version.txt"
    apk info -v > "$snapshot/packages.unsorted"
    sort "$snapshot/packages.unsorted" > "$snapshot/packages.txt"
    rm "$snapshot/packages.unsorted"
    cp -p /etc/apk/world "$snapshot/packages-world.txt"
    printf 'path\ttarget\n' > "$snapshot/service-links.tsv"
    for link in /etc/rc.d/*; do
        test -L "$link" || continue
        printf '%s\t%s\n' "${link#/}" "$(readlink "$link")"
    done >> "$snapshot/service-links.tsv"
    cp -p "$profile/preserve-paths.txt" "$snapshot/preserve-paths.txt"
    /sbin/sysupgrade -l > "$snapshot/sysupgrade-paths.txt"
    test -z "$(uci changes)"
    find /etc/config /etc/honk/config.d -type f -exec sha256sum '{}' + \
        > "$snapshot/critical-before.sha256"
    sha256sum /etc/honk/config.dae /usr/bin/honk-core /etc/init.d/honk \
        /usr/share/rpcd/acl.d/luci-f50-thermal.json \
        /usr/share/luci/menu.d/luci-app-doona.json >> "$snapshot/critical-before.sha256"
}

capture_settings() {
    if /etc/init.d/honk running; then
        resume_honk=1
        /etc/init.d/honk stop
        while /etc/init.d/honk running; do sleep 1; done
    fi
    # The stopped process has closed SQLite and its WAL before tar reads them.
    /sbin/sysupgrade -b "$snapshot/settings.tar.gz" > "$snapshot/sysupgrade.log" 2>&1
    resume_service
    sha256sum -c "$snapshot/critical-before.sha256" > "$snapshot/critical-after.log"
}

capture_kernel_files() {
    kernel=$(cat "$snapshot/kernel.txt")
    test -d "/lib/modules/$kernel"
    tar -czf "$snapshot/runtime.tar.gz" -C / "lib/modules/$kernel" \
        mnt/mu300-disk/boot/device-ramdisk.lz4 \
        mnt/mu300-disk/boot/installed.id mnt/mu300-disk/boot/installed.kernel \
        mnt/mu300-disk/boot/installed.tag mnt/mu300-disk/boot/kernel \
        mnt/mu300-disk/boot/written.sha256
    zcat /proc/config.gz > "$snapshot/running-kernel.config"
    cat /sys/kernel/btf/vmlinux > "$snapshot/running-vmlinux.btf"
    cat /proc/sys/net/core/bpf_jit_enable > "$snapshot/bpf-jit-enable.txt"
    sha256sum -c "$profile/kernel-bundle.sha256"
    bundle=$(awk 'NR == 1 {print $2}' "$profile/kernel-bundle.sha256")
    test "$(tar -xzOf "$bundle" ./kernel.release)" = "$kernel"
    cp -p "$bundle" "$snapshot/$(basename "$bundle")"
    (cd "$snapshot" && sha256sum settings.tar.gz runtime.tar.gz) \
        > "$snapshot/device-archives.sha256"
}

record_inventory
capture_settings
capture_kernel_files
rm "$snapshot/INCOMPLETE"
sync
echo "SNAPSHOT_CAPTURED: $snapshot"
