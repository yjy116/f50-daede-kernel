"""Exercise actual wrapper control flow with explicit upstream-service doubles."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from patch_init import patch_init

HERE = Path(__file__).resolve().parent
BASH = r'C:\Program Files\Git\bin\bash.exe' if __import__('os').name == 'nt' else shutil.which('bash')
HARNESS = r'''
. "$1"
F50_STARTED_MARKER="$2/started"
TRACE="$2/trace"
CORE=0; WEB=0
uci() {
    case "$*" in
        '-q get easytier.@easytier[0].enabled') printf '%s' "$CORE" ;;
        '-q get easytier.@easytier[0].web_enabled') printf '%s' "$WEB" ;;
        *) printf 'UNEXPECTED UCI\n' >>"$TRACE"; return 99 ;;
    esac
}
logger() { printf 'ERROR\n' >>"$TRACE"; }
start_service_upstream() { test -f "$F50_STARTED_MARKER" || return 91; printf 'START\n' >>"$TRACE"; }
stop_service_upstream() { printf 'STOP\n' >>"$TRACE"; }
'''


class WrapperTests(unittest.TestCase):
    def execute(self, commands):
        with tempfile.TemporaryDirectory() as temporary:
            result = subprocess.run([BASH, '--noprofile', '--norc', '-c', HARNESS + commands,
                                     'test', (HERE / 'wrappers.sh').as_posix(),
                                     Path(temporary).as_posix()], capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            path = Path(temporary) / 'trace'
            return path.read_text() if path.exists() else ''

    def test_never_enabled_start_and_stop_do_nothing(self):
        trace = self.execute('start_service; stop_service; test ! -e "$F50_STARTED_MARKER"')
        self.assertEqual(trace, '')

    def test_enabled_then_disabled_still_cleans_up(self):
        trace = self.execute('CORE=1; start_service; CORE=0; stop_service; test ! -e "$F50_STARTED_MARKER"')
        self.assertEqual(trace, 'START\nSTOP\n')

    def test_web_only_and_volatile_marker_recreation(self):
        trace = self.execute('WEB=1; start_service; rm "$F50_STARTED_MARKER"; start_service; test -f "$F50_STARTED_MARKER"')
        self.assertEqual(trace, 'START\nSTART\n')

    def test_upstream_stop_failure_is_exposed_and_marker_retained(self):
        trace = self.execute('CORE=1; start_service; CORE=0; stop_service_upstream() { return 17; }; '
                             'stop_service; status=$?; test "$status" = 17 && test -f "$F50_STARTED_MARKER"')
        self.assertEqual(trace, 'START\n')

    def test_unwritable_marker_exposes_error_without_starting(self):
        trace = self.execute('CORE=1; F50_STARTED_MARKER="$2/missing/started"; '
                             'start_service; test "$?" = 1')
        self.assertEqual(trace, 'ERROR\n')


class PatchTests(unittest.TestCase):
    def test_unexpected_source_is_rejected(self):
        with self.assertRaises(ValueError):
            patch_init(b'#!/bin/sh\nstart_service() { changed; }\n')


if __name__ == '__main__':
    unittest.main()
