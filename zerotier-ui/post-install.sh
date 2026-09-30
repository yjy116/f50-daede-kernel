#!/bin/sh
# Standard OpenWrt package lifecycle, followed by LuCI cache refresh only.
[ "${IPKG_NO_SCRIPT:-}" = "1" ] && exit 0
if [ ! -s "${IPKG_INSTROOT:-}/lib/functions.sh" ]; then
	echo 'luci-app-zerotier: required /lib/functions.sh is missing' >&2
	exit 1
fi
. "${IPKG_INSTROOT:-}/lib/functions.sh"
export root="${IPKG_INSTROOT:-}"
export pkgname='luci-app-zerotier'
add_group_and_user || exit $?
default_postinst || exit $?
[ -n "${IPKG_INSTROOT:-}" ] && exit 0
# Regenerable LuCI caches only; no UCI, firewall or ZeroTier state is changed.
rm -rf /tmp/luci-indexcache /tmp/luci-indexcache.* /tmp/luci-modulecache || exit $?
/etc/init.d/rpcd restart || exit $?
/etc/init.d/uhttpd restart || exit $?
exit 0
