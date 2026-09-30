#!/bin/sh
[ "${IPKG_NO_SCRIPT:-}" = 1 ] && exit 0
if [ ! -s "${IPKG_INSTROOT:-}/lib/functions.sh" ]; then
    echo '@PACKAGE@: missing OpenWrt lifecycle helpers' >&2
    exit 1
fi
. "${IPKG_INSTROOT:-}/lib/functions.sh"
export root="${IPKG_INSTROOT:-}"
export pkgname='@PACKAGE@'
add_group_and_user || exit $?
default_postinst || exit $?
exit 0
