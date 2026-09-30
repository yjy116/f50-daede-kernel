"""Menu transformation must preserve the backend, scripts and all other bytes."""
import copy
import hashlib
import json
import unittest

from policy import MENU_PATH, UI_NAME, UI_VERSION, audit_package, expected_info, patch_menu

ORIGINAL = b'{"admin/services/tailscale":{"title":"Tailscale","order":90,"action":{"type":"view","path":"tailscale"}}}'


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.source = {
            'info': {'name': UI_NAME, 'version': '26.270.72870~a24d1f2',
                     'description': 'UI', 'depends': ['libc', 'tailscale'], 'installed-size': 1000},
            'files': {MENU_PATH: {'size': len(ORIGINAL), 'sha256': hashlib.sha256(ORIGINAL).hexdigest(),
                                 'mode': 420, 'mtime': 123},
                      'usr/share/rpcd/ucode/tailscale.uc': {'sha256': 'original'}},
            'directories': {'': {'mode': 493}}, 'scripts': {'post-install': b'original'},
            'package_fields': {}, 'signature_blocks': 0,
        }
        self.options = {'name': UI_NAME, 'version': UI_VERSION, 'original_menu': ORIGINAL}
        self.patched = patch_menu(ORIGINAL)
        self.candidate = copy.deepcopy(self.source)
        self.candidate['signature_blocks'] = 1
        self.candidate['files'][MENU_PATH].update(size=len(self.patched),
            sha256=hashlib.sha256(self.patched).hexdigest())
        self.candidate['info'] = expected_info(self.source['info'], self.options)

    def test_menu_has_parent_and_preserves_view_action(self):
        result = json.loads(self.patched)
        self.assertEqual(set(result), {'admin/vpn', 'admin/vpn/tailscale'})
        self.assertEqual(result['admin/vpn']['action'], {'type': 'firstchild'})
        self.assertEqual(result['admin/vpn/tailscale'], json.loads(ORIGINAL)['admin/services/tailscale'])
        audit_package(self.source, self.candidate, self.options)

    def test_backend_permissions_scripts_and_extra_payload_rejected(self):
        changes = [lambda p: p['files']['usr/share/rpcd/ucode/tailscale.uc'].update(sha256='changed'),
                   lambda p: p['files'][MENU_PATH].update(mode=493),
                   lambda p: p['scripts'].update({'post-install': b'changed'}),
                   lambda p: p['info'].update(depends=['libc']),
                   lambda p: p['files'].update({'extra': {'sha256': 'extra'}})]
        for change in changes:
            candidate = copy.deepcopy(self.candidate)
            change(candidate)
            with self.subTest(change=change), self.assertRaises(ValueError):
                audit_package(self.source, candidate, self.options)

    def test_unknown_menu_shape_fails(self):
        with self.assertRaises(ValueError):
            patch_menu(b'{"admin/services/different":{}}')

    def test_translation_only_pins_paired_ui(self):
        info = dict(self.source['info'], name='luci-i18n-tailscale-community-zh-cn',
                    depends=['libc', UI_NAME])
        options = {'name': info['name'], 'version': UI_VERSION}
        expected = expected_info(info, options)
        self.assertEqual(expected['depends'], ['libc', UI_NAME + '=' + UI_VERSION])
        self.assertEqual(expected['installed-size'], info['installed-size'])
