#!/bin/sh
if [ ! -s "${IPKG_INSTROOT:-}/lib/functions.sh" ]; then
    echo '@PACKAGE@: missing OpenWrt lifecycle helpers' >&2
    exit 1
fi
. "${IPKG_INSTROOT:-}/lib/functions.sh"
export root="${IPKG_INSTROOT:-}"
export pkgname='@PACKAGE@'
default_prerm || exit $?

