"""Exact Tailscale menu-only payload change and paired translation metadata."""
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'packaging'))
from apk3 import require

UI_NAME = 'luci-app-tailscale-community'
UI_VERSION = '26.270.72870~a24d1f2-r1'
ZH_NAME = 'luci-i18n-tailscale-community-zh-cn'
MENU_PATH = 'usr/share/luci/menu.d/luci-app-tailscale-community.json'
DESCRIPTION = '; F50 adaptation: persistent VPN menu; see packaging-manifest.json'


def patch_menu(original):
    menu = json.loads(original)
    require(set(menu) == {'admin/services/tailscale'}, 'Unreviewed upstream menu paths')
    entry = menu['admin/services/tailscale']
    require(entry == {'title': 'Tailscale', 'order': 90,
                      'action': {'type': 'view', 'path': 'tailscale'}}, 'Unreviewed upstream menu entry')
    result = {'admin/vpn': {'title': 'VPN', 'order': 45, 'action': {'type': 'firstchild'}},
              'admin/vpn/tailscale': entry}
    return (json.dumps(result, indent='\t', ensure_ascii=False) + '\n').encode()


def expected_info(info, options):
    require(info['name'] == options['name'], 'Unexpected package name')
    dependencies = list(info['depends'])
    delta = 0
    if info['name'] == UI_NAME:
        original = options['original_menu']
        delta = len(patch_menu(original)) - len(original)
    else:
        require(info['name'] == ZH_NAME, 'Unreviewed package')
        require(dependencies.count(UI_NAME) == 1, 'Unexpected translation dependency')
        dependencies = [UI_NAME + '=' + UI_VERSION if dep == UI_NAME else dep for dep in dependencies]
    return dict(info, version=options['version'], depends=sorted(dependencies),
                description=info['description'] + DESCRIPTION,
                **{'installed-size': info['installed-size'] + delta})


def expected_files(source, options):
    result = dict(source['files'])
    if options['name'] == UI_NAME:
        original = options['original_menu']
        require(result[MENU_PATH]['sha256'] == hashlib.sha256(original).hexdigest(),
                'Menu does not match source package')
        patched = patch_menu(original)
        result[MENU_PATH] = dict(result[MENU_PATH], size=len(patched),
                                 sha256=hashlib.sha256(patched).hexdigest())
    return result


def audit_package(source, candidate, options):
    require(candidate['files'] == expected_files(source, options), 'Unreviewed payload change')
    for field in ('directories', 'scripts', 'package_fields'):
        require(candidate[field] == source[field], f'Unreviewed {field} change')
    require(source['signature_blocks'] == 0 and candidate['signature_blocks'] == 1,
            'Expected unsigned upstream and one output signature')
    expected = {k: v for k, v in expected_info(source['info'], options).items() if k != 'hashes'}
    actual = {k: v for k, v in candidate['info'].items() if k != 'hashes'}
    require(actual == expected, f'Unexpected metadata: actual={actual!r}, expected={expected!r}')
    return {'payload_changes': [MENU_PATH] if options['name'] == UI_NAME else [],
            'metadata_changes': {k: {'before': source['info'].get(k), 'after': candidate['info'].get(k)}
                                 for k in sorted(candidate['info'])
                                 if source['info'].get(k) != candidate['info'][k]},
            'files': candidate['files'], 'directories': candidate['directories'],
            'lifecycle_script_changes': [],
            'scripts': {name: {'size': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
                        for name, body in candidate['scripts'].items()}}


def audit_routes(root):
    menu = json.loads((root / MENU_PATH).read_bytes())
    require(set(menu) == {'admin/vpn', 'admin/vpn/tailscale'}, 'Unexpected output menu')
    view = root / 'www/luci-static/resources/view/tailscale.js'
    require(view.is_file() and menu['admin/vpn/tailscale']['action']['path'] == 'tailscale',
            'Menu view target missing')
    inspected = []
    for path in sorted(root.rglob('*')):
        if not path.is_file() or path.suffix not in ('.js', '.json', '.uc'):
            continue
        require(b'services' not in path.read_bytes(), f'Unexpected old services reference: {path.name}')
        inspected.append(path.relative_to(root).as_posix())
    return {'route': 'admin/vpn/tailscale', 'view': view.relative_to(root).as_posix(),
            'inspected': inspected, 'old_services_references': []}
