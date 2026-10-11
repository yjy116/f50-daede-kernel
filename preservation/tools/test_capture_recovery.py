"""Exercise capture.sh recovery functions with injected external service results."""
from dataclasses import dataclass
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


SOURCE = Path(os.environ.get("F50_CAPTURE_TEST_SOURCE", Path(__file__).with_name("capture.sh")))
SUITE_TIMEOUT_SECONDS = 60
CASE_TIMEOUT_SECONDS = 5
START_FAILED = 7
WAIT_EXPIRED = 124
EARLIER_FAILURE = 9
WINDOWS_BASH = Path("C:/Program Files/Git/bin/bash.exe")


def recovery_functions():
    source = SOURCE.read_text(encoding="utf-8")
    functions = []
    for name in ("resume_service", "finish"):
        matches = re.findall(rf"^{name}\(\) \{{\n.*?^\}}", source, re.MULTILINE | re.DOTALL)
        if len(matches) != 1:
            raise ValueError(f"Expected one complete {name} function in capture.sh")
        functions.append(matches[0])
    # Substitute only the two external dependencies, retaining all real branches.
    return "\n".join(functions).replace("/etc/init.d/honk", "injected_honk").replace(
        "/opt/mu300/bin/busybox timeout", "injected_timeout"
    )


def bash_path():
    executable = str(WINDOWS_BASH) if os.name == "nt" else shutil.which("bash")
    if not executable or not Path(executable).is_file():
        raise RuntimeError("Bash is required for isolated capture.sh function tests")
    return executable


DEPENDENCIES = r"""
injected_honk() {
    [ "$#" -eq 1 ] && [ "$1" = start ] || return 98
    return "$START_STATUS"
}
injected_timeout() {
    [ "$#" -eq 4 ] && [ "$1" = 30 ] && [ "$2" = sh ] && [ "$3" = -c ] || return 98
    [ "$4" = 'while ! injected_honk running; do sleep 1; done' ] || return 98
    return "$WAIT_STATUS"
}
"""
DIRECT_CALL = r"""
if resume_service; then result=0; else result=$?; fi
printf 'STATE:%s\n' "$resume_honk"
exit "$result"
"""


@dataclass(frozen=True)
class RecoveryResult:
    process: subprocess.CompletedProcess
    incomplete: bool


def run_recovery(*, start_status=0, wait_status=0, finish_status=None, resume="1"):
    context = f"START_STATUS={start_status}\nWAIT_STATUS={wait_status}\nresume_honk='{resume}'\n"
    action = DIRECT_CALL if finish_status is None else f"trap finish EXIT\nexit {finish_status}\n"
    script = "set -eu\n" + context + DEPENDENCIES + recovery_functions() + "\n" + action
    with tempfile.TemporaryDirectory() as directory:
        marker = Path(directory) / "INCOMPLETE"
        marker.touch()
        process = subprocess.run(
            [bash_path(), "--noprofile", "--norc", "--posix", "-s"], input=script,
            text=True, capture_output=True, cwd=directory, timeout=CASE_TIMEOUT_SECONDS,
        )
        return RecoveryResult(process, marker.is_file())


class CaptureRecoveryTests(unittest.TestCase):
    def assert_failed_recovery(self, result):
        self.assertNotEqual(result.process.returncode, 0, result.process.stdout)
        self.assertTrue(result.incomplete)
        self.assertIn("ERROR:", result.process.stderr)
        self.assertNotIn("HONK_RUNNING_RESTORED", result.process.stdout)

    def test_start_failure_keeps_pending_resume_and_incomplete(self):
        result = run_recovery(start_status=START_FAILED)
        self.assert_failed_recovery(result)
        self.assertIn("STATE:1\n", result.process.stdout)

    def test_wait_timeout_keeps_pending_resume_and_incomplete(self):
        result = run_recovery(wait_status=WAIT_EXPIRED)
        self.assert_failed_recovery(result)
        self.assertIn("STATE:1\n", result.process.stdout)

    def test_successful_running_confirmation_clears_pending_resume(self):
        result = run_recovery()
        self.assertEqual(result.process.returncode, 0, result.process.stderr)
        self.assertIn("STATE:\n", result.process.stdout)
        self.assertIn("HONK_RUNNING_RESTORED", result.process.stdout)
        self.assertEqual(result.process.stderr, "")
        self.assertTrue(result.incomplete)  # Only the complete capture may remove it.

    def test_originally_stopped_service_is_not_started(self):
        result = run_recovery(resume="", start_status=START_FAILED, wait_status=WAIT_EXPIRED)
        self.assertEqual(result.process.returncode, 0, result.process.stderr)
        self.assertEqual(result.process.stdout, "STATE:\n")
        self.assertEqual(result.process.stderr, "")

    def test_exit_cleanup_start_failure_cannot_be_swallowed(self):
        result = run_recovery(start_status=START_FAILED, finish_status=0)
        self.assert_failed_recovery(result)
        self.assertIn("snapshot remains incomplete", result.process.stderr)

    def test_exit_cleanup_timeout_cannot_be_swallowed(self):
        result = run_recovery(wait_status=WAIT_EXPIRED, finish_status=0)
        self.assert_failed_recovery(result)
        self.assertIn("snapshot remains incomplete", result.process.stderr)

    def test_exit_cleanup_preserves_original_error_after_recovery(self):
        result = run_recovery(finish_status=EARLIER_FAILURE)
        self.assertEqual(result.process.returncode, EARLIER_FAILURE)
        self.assertIn("HONK_RUNNING_RESTORED", result.process.stdout)
        self.assertTrue(result.incomplete)

    def test_exit_cleanup_returns_success_only_when_recovery_succeeds(self):
        result = run_recovery(finish_status=0)
        self.assertEqual(result.process.returncode, 0, result.process.stderr)
        self.assertIn("HONK_RUNNING_RESTORED", result.process.stdout)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--worker":
        unittest.main(argv=[sys.argv[0], *sys.argv[2:]])
        return
    try:
        result = subprocess.run(
            [sys.executable, "-B", str(Path(__file__).resolve()), "--worker", *sys.argv[1:]],
            timeout=SUITE_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        print("FAIL: capture recovery tests exceeded the 60-second hard timeout", file=sys.stderr)
        raise SystemExit(WAIT_EXPIRED)
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
