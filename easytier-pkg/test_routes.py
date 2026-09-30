"""Exercise route registration and page-link consistency before APK creation."""
from pathlib import Path
import tempfile
import unittest

from routes import audit_routes


class RouteTests(unittest.TestCase):
    def tree(self, root, link='admin/vpn/easytier/status'):
        controller = root / 'usr/lib/lua/luci/controller/easytier.lua'
        controller.parent.mkdir(parents=True)
        controller.write_text('entry({"admin", "vpn"}, firstchild(), "VPN", 45)\n'
                              'entry({"admin", "vpn", "easytier"}, firstchild())\n'
                              'entry({"admin", "vpn", "easytier", "status"}, call("status"))')
        page = root / 'usr/lib/lua/luci/view/easytier/status.htm'
        page.parent.mkdir(parents=True)
        page.write_text('<%=url("' + link + '")%>')

    def test_registered_vpn_url_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.tree(root)
            result = audit_routes(root)
            self.assertEqual(result['root'], 'admin/vpn/easytier')
            self.assertEqual(result['references'], 1)

    def test_old_services_path_or_dangling_url_is_rejected(self):
        for link in ('admin/services/easytier/status', 'admin/vpn/easytier/missing'):
            with self.subTest(link=link), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.tree(root, link)
                with self.assertRaises(ValueError):
                    audit_routes(root)

    def test_missing_parent_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.tree(root)
            controller = root / 'usr/lib/lua/luci/controller/easytier.lua'
            controller.write_text(controller.read_text().split('\n', 1)[1])
            with self.assertRaises(ValueError):
                audit_routes(root)
