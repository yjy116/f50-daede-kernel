"""Validate public build-fixture DNS addresses; never return unconditional success."""
import ipaddress
import re
import sys


def valid(kind, value):
    if kind == 'hostname':
        return bool(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*', value))
    versions = {'ip4addr': 4, 'ip6addr': 6}
    if kind not in versions:
        raise ValueError('Unexpected datatype')
    try:
        return ipaddress.ip_address(value).version == versions[kind]
    except ValueError:
        return False


if __name__ == '__main__':
    sys.exit(0 if valid(*sys.argv[1:]) else 1)
