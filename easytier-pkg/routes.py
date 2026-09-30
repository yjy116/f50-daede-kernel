"""Check the pinned upstream VPN controller and every Lua/template route link."""
import re

from package_policy import require

QUOTED = re.compile(r'''["']([^"']+)["']''')
ENTRIES = re.compile(r'\bentry\s*\(\s*\{([^}]+)\}')
LINKS = re.compile(r'\b(?:build_url|url)\s*\(([^)]+)\)')


def audit_routes(root):
    base = root / 'usr/lib/lua/luci'
    controller = (base / 'controller/easytier.lua').read_text(encoding='utf-8')
    registered = {'/'.join(QUOTED.findall(arguments)) for arguments in ENTRIES.findall(controller)}
    require({'admin/vpn', 'admin/vpn/easytier'} <= registered, 'Missing VPN parent or EasyTier menu')
    require(all(route == 'admin/vpn' or route.startswith('admin/vpn/easytier')
                for route in registered), 'EasyTier controller has a non-VPN route')
    references = []
    for path in sorted(base.rglob('*')):
        if not path.is_file() or path.suffix not in ('.lua', '.htm'):
            continue
        text = path.read_text(encoding='utf-8')
        require('services' not in text, f'Unexpected services reference: {path.name}')
        for arguments in LINKS.findall(text):
            route = '/'.join(QUOTED.findall(arguments))
            require(route in registered, f'Unregistered EasyTier link: {route}')
            references.append({'file': path.relative_to(root).as_posix(), 'route': route})
    require(bool(references), 'Missing EasyTier page route references')
    return {'root': 'admin/vpn/easytier', 'registered': sorted(registered),
            'references': len(references), 'links': references, 'payload_changes': []}
