"""Execute the real shell config/network helpers with isolated input and paths."""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
LIB = ROOT / 'root/usr/libexec/zerotier-f50'
BASH = shutil.which('bash') if os.name != 'nt' else r'C:\Program Files\Git\bin\bash.exe'
NETWORK_ID = '1234567890abcdef'


def shell_path(path):
    text = Path(path).as_posix()
    return '/' + text[0].lower() + text[2:] if os.name == 'nt' else text


def fixture(values):
    cases = [f'{shlex.quote(key)}) fixture_value={shlex.quote(value)};;' for key, value in values.items()]
    return '\n'.join([
        'config_get() { local fixture_value=${4-}; case "$2:$3" in', *cases,
        'esac; printf -v "$1" "%s" "$fixture_value"; }',
        'config_foreach() { "$1" network1; }'])


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.runtime = self.base / 'run'
        self.state = self.base / 'state'
        (self.runtime / 'networks.d').mkdir(parents=True)
        self.addCleanup(self.temp.cleanup)

    def run_shell(self, script, values=None):
        values = values or {}
        values = {key: shell_path(value) if key.endswith('config_path') and value else value
                  for key, value in values.items()}
        sources = '\n'.join(f'. {shlex.quote(path.as_posix())}' for path in sorted(LIB.glob('*.sh')))
        setup = fixture(values) + '\n' + sources
        setup += '\nZT_RUNTIME=' + shlex.quote(self.runtime.as_posix())
        setup += '\nZT_STATE=' + shlex.quote(self.state.as_posix())
        return subprocess.run([BASH, '-c', setup + '\n' + script],
                              capture_output=True, text=True, timeout=10,
                              env=dict(os.environ, MSYS='winsymlinks:nativestrict'))

    def test_boolean_default_and_explicit_false(self):
        result = self.run_shell('zt_bool network1 enabled 1; zt_bool network1 allow_managed 1',
                                {'network1:allow_managed': '0'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ['1', '0'])

    def test_invalid_boolean_fails_without_echoing_value(self):
        result = self.run_shell('zt_bool network1 enabled 1', {'network1:enabled': 'private-invalid'})
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('private-invalid', result.stderr)

    def test_disabled_network_removes_only_exact_managed_files(self):
        folder = self.runtime / 'networks.d'
        for name in [NETWORK_ID + '.conf', NETWORK_ID + '.local.conf', 'fedcba0987654321.conf']:
            (folder / name).write_text('preserve-or-remove', encoding='utf-8')
        result = self.run_shell('zt_validate_networks && zt_sync_networks',
                                {'network1:id': NETWORK_ID, 'network1:enabled': '0'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sorted(path.name for path in folder.iterdir()), ['fedcba0987654321.conf'])

    def test_legacy_network_enabled_and_managed_defaults(self):
        result = self.run_shell('zt_validate_networks && zt_sync_networks', {'network1:id': NETWORK_ID})
        self.assertEqual(result.returncode, 0, result.stderr)
        content = (self.runtime / 'networks.d' / (NETWORK_ID + '.local.conf')).read_text()
        self.assertEqual(content, 'allowManaged=1\nallowGlobal=0\nallowDefault=0\nallowDNS=0\n')

    def test_invalid_id_fails_before_touching_network_files(self):
        marker = self.runtime / 'networks.d' / 'existing.conf'
        marker.write_text('original')
        result = self.run_shell('zt_validate_networks && zt_sync_networks', {'network1:id': '../invalid'})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(marker.read_text(), 'original')

    def test_deleted_previously_owned_network_is_removed(self):
        self.state.mkdir()
        old = 'fedcba0987654321'
        (self.state / 'network-ids').write_text(old + '\n', newline='\n')
        (self.runtime / 'networks.d' / (old + '.conf')).write_text('old')
        result = self.run_shell('zt_validate_networks && zt_sync_networks', {'network1:id': NETWORK_ID})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.runtime / 'networks.d' / (old + '.conf')).exists())

    @unittest.skipIf(os.name == 'nt', 'Native symlink permission unavailable; Linux CI must run this test')
    def test_linked_persistent_network_disable_preserves_unknown_network_and_identity(self):
        persistent = self.base / 'persistent'
        (persistent / 'networks.d').mkdir(parents=True)
        (persistent / 'identity.secret').write_text('existing-test-identity')
        for name in [NETWORK_ID + '.conf', 'fedcba0987654321.conf']:
            (persistent / 'networks.d' / name).write_text('network')
        values = {'network1:id': NETWORK_ID, 'network1:enabled': '0',
                  'global:config_path': persistent.as_posix()}
        result = self.run_shell('zt_validate_global && zt_prepare_runtime', values)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((persistent / 'networks.d' / (NETWORK_ID + '.conf')).exists())
        self.assertTrue((persistent / 'networks.d' / 'fedcba0987654321.conf').exists())
        self.assertEqual((persistent / 'identity.secret').read_text(), 'existing-test-identity')
        result = self.run_shell('zt_validate_global && zt_prepare_runtime', values)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.runtime.is_symlink())

    def test_missing_source_path_does_not_remove_runtime(self):
        marker = self.runtime / 'identity.secret'
        marker.write_text('keep')
        values = {'network1:id': NETWORK_ID, 'global:config_path': (self.base / 'missing').as_posix()}
        result = self.run_shell('zt_validate_global && zt_prepare_runtime', values)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(marker.read_text(), 'keep')

    def test_invalid_identity_does_not_overwrite_existing_identity(self):
        marker = self.runtime / 'identity.secret'
        marker.write_text('keep')
        result = self.run_shell("zerotier-idtool() { return 1; }; ZT_SECRET=0123456789:0:abcdef:abcd; zt_prepare_identity")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(marker.read_text(), 'keep')

    def test_public_identity_is_not_accepted_as_private_identity(self):
        marker = self.runtime / 'identity.secret'
        marker.write_text('keep')
        result = self.run_shell("zerotier-idtool() { return 0; }; ZT_SECRET=0123456789:0:abcdef; zt_prepare_identity")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(marker.read_text(), 'keep')

    def test_uppercase_disabled_id_removes_legacy_case_file(self):
        marker = self.runtime / 'networks.d' / (NETWORK_ID.upper() + '.conf')
        marker.write_text('legacy')
        result = self.run_shell('zt_validate_networks && zt_sync_networks',
                                {'network1:id': NETWORK_ID.upper(), 'network1:enabled': '0'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(marker.exists())

    def test_disabled_start_preserves_existing_runtime(self):
        marker = self.runtime / 'identity.secret'
        marker.write_text('keep')
        init = ROOT / 'root/etc/init.d/zerotier'
        self.assertTrue(init.is_file(), 'init implementation is required')
        source = init.read_text()
        callbacks = source[source.index('start_service()'):]
        result = self.run_shell('config_load() { :; };\n' + callbacks + '\nstart_service',
                                {'network1:id': NETWORK_ID, 'global:enabled': '0'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(marker.read_text(), 'keep')

    def test_start_failure_survives_rc_common_post_start_callback(self):
        source = (ROOT / 'root/etc/init.d/zerotier').read_text()
        callbacks = source[source.index('start_service()'):]
        script = 'config_load() { :; };\n' + callbacks + '\nstart_service; true; service_started'
        result = self.run_shell(script, {'network1:id': '../invalid', 'global:enabled': '1'})
        self.assertNotEqual(result.returncode, 0)

    def test_stop_failure_survives_rc_common_post_stop_callback(self):
        source = (ROOT / 'root/etc/init.d/zerotier').read_text()
        callbacks = source[source.index('start_service()'):]
        script = 'rm() { return 1; }; logger() { :; }; fw4() { return 0; };\n'
        result = self.run_shell(script + callbacks + '\nstop_service; true; service_stopped')
        self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
