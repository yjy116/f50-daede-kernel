#!/bin/sh
# Usage: sh 03-install-official-kernel.sh ABSOLUTE_INPUT_DIRECTORY
# Run only AFTER a validated candidate has been renamed into openwrt and the old live root into openwrt.old.
# Executes the official updater unchanged. Does not reboot or claim runtime acceptance.
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$script_dir/migration-common.sh"
test "$#" -eq 1 || fail 'Expected the absolute verified input directory'
input=$1
require_input_directory "$input"
verify_published_assets "$input"
test / -ef "$F50_DISK/openwrt.old" || fail 'Expected to still run from the preserved old root'
test "$(cat "$F50_OLD/etc/mu300/image-version")" = "$F50_RELEASE"
test "$(tar -xzOf "$input/mu300-kernel-7.2.tar.gz" ./kernel.release)" = "$F50_KERNEL"
cmp -s "$input/mu300-update" "$F50_OLD/opt/mu300/bin/mu300-update" ||
    fail 'Candidate updater differs from the verified published updater'
MU300_RELEASE=$F50_RELEASE \
MU300_KERNEL_BUNDLE=$input/mu300-kernel-7.2.tar.gz \
MU300_BIN=$F50_OLD/opt/mu300/bin \
    sh "$F50_OLD/opt/mu300/bin/mu300-update" kernel 7.2
printf '%s\n' OFFICIAL_KERNEL_COMMAND_COMPLETED_READBACK_AND_REBOOT_VALIDATION_PENDING
