#!/bin/sh
# Usage: sh 02-carry-candidate.sh ABSOLUTE_INPUT_DIRECTORY EXPECTED_PACKAGES_TSV
# Run only AFTER the offline signed APK install and while Honk is stopped by the controller.
# The controller owns update exclusion and must restore Honk on failure; no service is started here.
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$script_dir/migration-common.sh"
test "$#" -eq 2 || fail 'Expected input directory and package TSV'
input=$1
expected=$2
require_input_directory "$input"
require_old_running
verify_published_assets "$input"
verify_image_metadata "$input"
verify_expected_packages "$expected" "$input"
require_quiesced_honk
test -z "$(uci changes)" || fail 'Uncommitted UCI changes require explicit handling before carry'
test ! -e "$F50_NEW/.mu300-carried" || fail 'Candidate already has a carry completion marker'
test ! -e "$F50_NEW/proc/1"
umask 077
# The historical root was assembled from the LuCI image while its directory remained named openwrt.
# The flavor below is an explicit migration input, not a rewrite of the old release identity.
MU300_LIB= "$F50_NEW/opt/mu300/bin/busybox" sh "$F50_NEW/opt/mu300/bin/mu300-update" \
    carry "$F50_OLD" "$F50_NEW" openwrt-luci copy > "$input/state/carry.log" 2>&1
test -e "$F50_NEW/.mu300-carried" || fail 'Official carry did not reach its completion marker'
if grep -q 'no list of the files\|There was no room to set them aside' "$input/state/carry.log"; then
    fail 'Migration lacked its historical manifest or omitted a conflicting file; inspect the private log'
fi
verify_image_metadata "$input"
verify_expected_packages "$expected" "$input"
if test -s "$F50_NEW/etc/mu300/user-packages/wanted"; then
    fail 'Packages remain scheduled for first-boot reinstall; resolve them before switching'
fi
# This is the next running root, not a long-term snapshot: retain this session's temporary
# authorized key for post-boot verification. The controller removes the exact key line from
# BOTH the active and rollback roots after acceptance, verifies rejection, then deletes its key pair.
# Long-term snapshots must exclude this key; the pre-upgrade snapshot was taken before it was added.
cp "$F50_NEW/etc/mu300/update-report" "$input/state/carry-report.txt"
rm "$F50_NEW/.mu300-carried"
sync
printf '%s\n' CARRY_COMPLETED_CUSTOM_FILES_SERVICES_AND_RUNTIME_VALIDATION_PENDING
