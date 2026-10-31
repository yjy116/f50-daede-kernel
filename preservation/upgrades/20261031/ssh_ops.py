"""Scoped SSH transport; keys, raw output and backups stay in private/."""
from pathlib import Path
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
PRIVATE = HERE / "private"
KEY = PRIVATE / "maintenance_key"
KNOWN_HOSTS = PRIVATE / "known_hosts"
HOST = "root@192.168.77.1"
DEFAULT_TIMEOUT = 60


def prepare_key():
    if KEY.exists():
        raise FileExistsError("Maintenance identity already exists")
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(KEY),
                    "-C", "f50-update-20261031"], check=True, timeout=DEFAULT_TIMEOUT)
    previous = HERE.parent / "update-20261011/private/known_hosts"
    shutil.copyfile(previous, KNOWN_HOSTS)


def connection():
    return ["ssh", "-T", "-i", str(KEY), "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10",
            "-o", "UserKnownHostsFile=" + str(KNOWN_HOSTS), HOST]


def run(script, *, timeout=DEFAULT_TIMEOUT):
    result = subprocess.run(connection() + ["sh -s"], input=script.encode(),
                            capture_output=True, timeout=timeout)
    if result.returncode:
        (PRIVATE / "ssh-error.log").write_bytes(result.stdout + result.stderr)
        raise RuntimeError("SSH command failed; inspect private/ssh-error.log")
    return result.stdout


def download(command, destination, *, timeout=DEFAULT_TIMEOUT):
    with destination.open("xb") as output:
        result = subprocess.run(connection() + [command], stdout=output,
                                stderr=subprocess.PIPE, timeout=timeout)
    if result.returncode:
        (PRIVATE / "download-error.log").write_bytes(result.stderr)
        raise RuntimeError("SSH download failed; partial file retained")


def upload(source, remote_path, *, timeout=DEFAULT_TIMEOUT):
    import shlex
    command = "umask 077; cat > " + shlex.quote(remote_path)
    with source.open("rb") as stream:
        result = subprocess.run(connection() + [command], stdin=stream,
                                capture_output=True, timeout=timeout)
    if result.returncode:
        (PRIVATE / "upload-error.log").write_bytes(result.stderr)
        raise RuntimeError("SSH upload failed; partial remote file retained")


if __name__ == "__main__":
    prepare_key()
    print("Maintenance identity prepared in restricted private directory")
