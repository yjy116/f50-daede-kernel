"""Run only the compiled SIPA regressions, with a hard 60-second execution limit."""

import json
import re
import subprocess
import sys
from pathlib import Path

TEST_TIMEOUT_SECONDS = 60


def find_test_executable(artifacts):
    messages = (artifacts / "test-compile.jsonl").read_text().splitlines()
    binaries = []
    for line in messages:
        item = json.loads(line)
        if item.get("reason") != "compiler-artifact":
            continue
        if item.get("executable") and item.get("profile", {}).get("test"):
            binaries.append(Path(item["executable"]))
    if len(binaries) != 1:
        raise RuntimeError(f"Expected one test executable, got {binaries}")
    return binaries[0]


def verify_result(result_text, completed, test_count):
    completed.check_returncode()
    summary = re.search(r"test result: ok\. (\d+) passed; 0 failed; 0 ignored;", result_text)
    if not summary or int(summary.group(1)) != test_count:
        raise RuntimeError("Selected tests were not all executed successfully")


def verify_ablation(result_text, completed, test_count):
    expected = "test result: FAILED. 0 passed; 1 failed; 0 ignored;"
    if completed.returncode != 101 or test_count != 1 or expected not in result_text:
        raise RuntimeError("Ablation did not produce exactly one real test failure")
    if "assertion" not in result_text:
        raise RuntimeError("Ablation failed without a regression assertion")


def run_regressions(artifacts, test_filter, ablation=False):
    executable = str(find_test_executable(artifacts))
    selected = subprocess.run(
        [executable, test_filter, "--list", "--format", "terse"],
        check=True, capture_output=True, text=True, timeout=TEST_TIMEOUT_SECONDS,
    ).stdout
    (artifacts / "selected-tests.txt").write_text(selected)
    tests = [line for line in selected.splitlines() if line.endswith(": test")]
    if not tests:
        raise RuntimeError(f"No tests selected by {test_filter!r}")
    with (artifacts / "test-results.txt").open("w") as result:
        completed = subprocess.run(
            [executable, test_filter, "--nocapture", "--test-threads=1"],
            stdout=result, stderr=subprocess.STDOUT, timeout=TEST_TIMEOUT_SECONDS,
        )
    result_text = (artifacts / "test-results.txt").read_text()
    print(result_text)
    verifier = verify_ablation if ablation else verify_result
    verifier(result_text, completed, len(tests))
    print(f"Verified {len(tests)} selected tests; expected_assertion_failure={ablation}.")


if __name__ == "__main__":
    if sys.argv[3:] not in ([], ["--ablation"]):
        raise ValueError("usage: run-tests.py ARTIFACTS FILTER [--ablation]")
    run_regressions(Path(sys.argv[1]), sys.argv[2], sys.argv[3:] == ["--ablation"])
