"""Remove only this session's authorization from active and rollback roots."""
import hashlib
import json
import subprocess

from ssh_ops import PRIVATE, KEY, connection, run, upload

TARGETS = {
    "active": "/etc/dropbear/authorized_keys",
    "rollback": "/mnt/mu300-disk/openwrt.old/etc/dropbear/authorized_keys",
}


def prepare_replacements():
    key = KEY.with_suffix(".pub").read_bytes().strip()
    result = {}
    for name, remote in TARGETS.items():
        data = run("set -eu\ntest -f " + remote + "\ntest ! -L " + remote + "\ncat " + remote + "\n")
        lines = data.splitlines(keepends=True)
        if sum(line.strip() == key for line in lines) != 1:
            raise ValueError("Expected one task authorization in " + name)
        cleaned = b"".join(line for line in lines if line.strip() != key)
        local = PRIVATE / ("authorization-" + name + ".after")
        local.write_bytes(cleaned)
        temporary = remote + ".f50-revoke-new"
        upload(local, temporary)
        result[name] = {"path": remote, "temporary": temporary,
                        "before": hashlib.sha256(data).hexdigest(),
                        "after": hashlib.sha256(cleaned).hexdigest(), "removed": 1}
    return result


def main():
    records = prepare_replacements()
    commands = ["set -eu"]
    for record in records.values():
        path, temporary = record["path"], record["temporary"]
        commands.append(f"test \"$(sha256sum {path} | cut -d' ' -f1)\" = {record['before']}")
        commands.append(f"test \"$(sha256sum {temporary} | cut -d' ' -f1)\" = {record['after']}")
        commands.extend([f"chmod 600 {temporary}", f"chown 0:0 {temporary}", f"mv {temporary} {path}"])
        commands.append(f"test \"$(sha256sum {path} | cut -d' ' -f1)\" = {record['after']}")
    commands.extend(["sync", "echo EXACT_AUTHORIZATIONS_REVOKED"])
    print(run("\n".join(commands) + "\n").decode())
    probe = subprocess.run(connection() + ["true"], capture_output=True, timeout=20)
    if probe.returncode != 255 or b"Permission denied" not in probe.stderr:
        raise RuntimeError("New maintenance authentication was not explicitly denied")
    report = {"status": "PASS", "roots": records, "new_authentication": "Permission denied",
              "other_authorization_lines": "byte-preserved", "private_key_pair_deleted": True}
    KEY.unlink()
    KEY.with_suffix(".pub").unlink()
    (PRIVATE / "maintenance-revocation.json").write_text(json.dumps(report, indent=2))
    print("MAINTENANCE_KEY_REVOKED_BOTH_ROOTS_AUTH_DENIED_KEY_PAIR_DELETED")


if __name__ == "__main__":
    main()
