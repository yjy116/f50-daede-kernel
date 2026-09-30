#!/bin/sh
# F50 p1 -> p2 update: retain boot links and UCI; do not start the service.
[ "${IPKG_NO_SCRIPT:-}" = 1 ] && exit 0
if [ ! -s "${IPKG_INSTROOT:-}/lib/functions.sh" ]; then
	echo 'zerotier p2: required OpenWrt lifecycle helpers are missing' >&2
	exit 1
fi
. "${IPKG_INSTROOT:-}/lib/functions.sh"
export root="${IPKG_INSTROOT:-}"
export pkgname=zerotier
add_group_and_user || exit $?
# Deliberately omit default_postinst: it runs package UCI defaults, commits UCI,
# and starts init services even during upgrades. Existing boot links stay.
exit 0
