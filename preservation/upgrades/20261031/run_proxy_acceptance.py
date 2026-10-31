"""Run the existing real HTTPS/flow acceptance through this task's pinned SSH session."""
import argparse
import importlib.util
import json
import re
import shlex
import subprocess

from ssh_ops import HERE, PRIVATE, connection

LEGACY = HERE.parent / "honk-sipa/verify-proxy.py"
TIMEOUT = 35


def load_validator():
    spec = importlib.util.spec_from_file_location("existing_proxy_acceptance", LEGACY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def device_curl(context, url, label):
    metrics = '\n{"http":"%{http_code}","remote":"%{remote_ip}","port":"%{local_port}","bytes":"%{size_download}"}'
    command = shlex.join(["curl", "-4", "--noproxy", "*", "-sS", "--connect-timeout",
                          "10", "--max-time", "25", "-w", metrics, url])
    result = subprocess.run(connection() + [command], capture_output=True, text=True, timeout=TIMEOUT)
    context.save(label + "-curl.json", {"exit": result.returncode, "stdout": result.stdout,
                                      "stderr": result.stderr})
    if result.returncode:
        raise RuntimeError(f"HTTPS request failed: {label}, exit={result.returncode}")
    body, values = result.stdout.rsplit("\n", 1)
    return body, json.loads(values)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("label")
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z0-9-]+", args.label):
        raise ValueError("Invalid evidence label")
    validator = load_validator()
    validator.OUTPUT = PRIVATE / args.label
    validator.curl = lambda url, label: device_curl(validator, url, label)
    validator.main()


if __name__ == "__main__":
    main()
