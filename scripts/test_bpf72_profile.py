"""Configuration overlay and release-input checks for the isolated 7.2.9 profile."""
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from merge_kernel_config import merge
from validate_kernel import expected_modules, read_config, verify_config

ROOT = Path(__file__).resolve().parents[1]


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_overlay_replaces_old_value_and_preserves_other_modules(self):
        base = self.root / 'base'
        base.write_text('CONFIG_BPF_JIT=n\nCONFIG_NFT_QUEUE=m\n# retained note\n')
        fragment = self.root / 'fragment'
        fragment.write_text('CONFIG_BPF_JIT=y\nCONFIG_LOCALVERSION="-f50-bpf1"\n')
        output = self.root / 'output'
        output.write_text(merge(base, fragment))
        self.assertEqual(read_config(output), {'CONFIG_BPF_JIT': 'y', 'CONFIG_NFT_QUEUE': 'm',
                                              'CONFIG_LOCALVERSION': '"-f50-bpf1"'})
        self.assertIn('# retained note', output.read_text())

    def test_overlay_rejects_ambiguous_duplicate_input(self):
        base = self.root / 'base'
        base.write_text('CONFIG_BPF_JIT=y\nCONFIG_BPF_JIT=n\n')
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            merge(base, ROOT / 'config/bpf72.config')

    def test_real_mediatek_kconfig_symbols_with_lowercase_x(self):
        base = self.root / 'base'
        base.write_text('CONFIG_MT76x02_LIB=m\nCONFIG_MT792x_USB=m\n')
        fragment = self.root / 'fragment'
        fragment.write_text('CONFIG_MT76x02_LIB=y\n')
        output = self.root / 'output'
        output.write_text(merge(base, fragment))
        self.assertEqual(read_config(output), {'CONFIG_MT76x02_LIB': 'y',
                                              'CONFIG_MT792x_USB': 'm'})

    def test_pinned_upstream_identical_epoll_duplicates_are_normalized(self):
        base = self.root / 'base'
        base.write_text('CONFIG_EPOLL=y\nCONFIG_EPOLL=y\nCONFIG_NFT_QUEUE=m\n')
        output = self.root / 'output'
        output.write_text(merge(base, ROOT / 'config/bpf72.config'))
        self.assertEqual(read_config(output)['CONFIG_EPOLL'], 'y')
        self.assertEqual(output.read_text().count('CONFIG_EPOLL='), 1)

    def test_actual_config_cannot_drop_requested_jit(self):
        fragment = ROOT / 'config/bpf72.config'
        text = fragment.read_text().replace('CONFIG_BPF_JIT=y', '# CONFIG_BPF_JIT is not set')
        (self.root / '.config').write_text(text)
        options = SimpleNamespace(config_extra=fragment, build_dir=self.root,
                                  local_version='-f50-bpf1')
        with self.assertRaisesRegex(ValueError, 'CONFIG_BPF_JIT'):
            verify_config(options)

    def test_actual_config_requires_candidate_suffix(self):
        fragment = ROOT / 'config/bpf72.config'
        (self.root / '.config').write_text(fragment.read_text())
        options = SimpleNamespace(config_extra=fragment, build_dir=self.root,
                                  local_version='-f50-dae1')
        with self.assertRaisesRegex(ValueError, 'LOCALVERSION'):
            verify_config(options)

    def test_module_manifest_rejects_bad_and_duplicate_names(self):
        path = self.root / 'manifest.json'
        for names in (['../sipa'], ['sipa', 'sipa']):
            path.write_text(json.dumps({'module_names': names}))
            with self.assertRaises(ValueError):
                expected_modules(SimpleNamespace(module_manifest=path))

    def test_historical_module_gate_is_preserved(self):
        self.assertEqual(len(expected_modules(SimpleNamespace(module_manifest=None))), 31)


if __name__ == '__main__':
    unittest.main()
