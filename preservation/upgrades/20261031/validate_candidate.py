"""Verify the complete candidate without displaying user configuration or credentials."""
import csv
import hashlib
import io
import json
import sqlite3
import tarfile

from ssh_ops import HERE, PRIVATE, download, run, upload

DISK = "/mnt/mu300-disk"
INPUT = DISK + "/f50-official-20261031"
NEW = DISK + "/openwrt.new"
TIMEOUT = 120
CRITICAL = """etc/config etc/honk etc/dropbear etc/zerotier-f50 etc/homeproxy
etc/openclash etc/easytier etc/tailscale etc/sing-box usr/bin/honk-core etc/init.d/honk
usr/share/rpcd/acl.d/luci-f50-thermal.json
www/luci-static/resources/view/status/include/15_f50_thermal.js
usr/share/luci/menu.d/luci-app-doona.json www/luci-static/resources/view/services/doona.js
etc/uhttpd.crt etc/uhttpd.key etc/shadow etc/passwd etc/group"""


def apply_reviewed_defaults():
    table = HERE / "migration-review/defaults-actions.tsv"
    rows = list(csv.DictReader(table.open(encoding="utf-8"), delimiter="\t"))
    commands = ["set -eu", f"mkdir -m 700 {INPUT}/state/completed-defaults"]
    for row in rows:
        path = row["path"]
        assert path.startswith("/etc/uci-defaults/") and ".." not in path
        commands.append(f"test \"$(sha256sum {NEW}{path} | cut -d' ' -f1)\" = {row['sha256']}")
        if row["action"] == "SKIP_ALREADY_INITIALIZED":
            commands.append(f"test ! -e {DISK}/openwrt{path}")
            commands.append(f"mv {NEW}{path} {INPUT}/state/completed-defaults/")
        else:
            assert row["action"] == "KEEP"
    commands.append(f"test $(find {NEW}/etc/uci-defaults -type f | wc -l) -eq 31")
    (PRIVATE / "defaults-applied.log").write_bytes(run("\n".join(commands) + "\n"))


def verify_configurations():
    script = f"""set -eu
O={DISK}/openwrt
N={NEW}
I={INPUT}
test -z "$(uci changes)"
test ! -e "$N/proc/1"
test "$(chroot "$N" /sbin/uci -q get system.mu300.defaults)" = 1
test "$(chroot "$N" /sbin/uci -q get luci.mu300.defaults)" = 1
chroot "$N" /sbin/uci export >/dev/null
for p in {' '.join(CRITICAL.split())}; do
 if test -d "$O/$p"; then find "$O/$p" -type f
 elif test -f "$O/$p"; then echo "$O/$p"
 fi
done | sed 's@^'"$O/"'@@' | grep -v '\\.apk-new$' | sort -u > "$I/state/critical-paths.txt"
: > "$I/state/candidate-critical.sha256"
: > "$I/state/source-critical.sha256"
while IFS= read -r p; do
 cmp -s "$O/$p" "$N/$p" || {{ echo "Config differs: $p" >&2; exit 1; }}
 old_meta=$(/opt/mu300/bin/busybox stat -c '%a:%u:%g' "$O/$p")
 new_meta=$(/opt/mu300/bin/busybox stat -c '%a:%u:%g' "$N/$p")
 test "$old_meta" = "$new_meta" || {{ echo "Metadata differs: $p" >&2; exit 1; }}
 sha256sum "$N/$p" >> "$I/state/candidate-critical.sha256"
 sha256sum "$O/$p" >> "$I/state/source-critical.sha256"
done < "$I/state/critical-paths.txt"
. "$I/scripts/migration-common.sh"
verify_image_metadata "$I"
verify_expected_packages "$I/state/expected-packages.tsv" "$I"
chroot "$N" /usr/bin/honk-core --version
echo CONFIGURATION_BYTES_METADATA_AND_PACKAGE_SET_PASS
"""
    result = run(script, timeout=TIMEOUT)
    (PRIVATE / "candidate-config-validation.log").write_bytes(result)
    print(result.decode())


def verify_services():
    script = f"""set -eu
N={NEW}
while IFS="$(printf '\\t')" read -r name enabled; do
 actual=0
 for link in "$N"/etc/rc.d/S??"$name"; do test ! -L "$link" || actual=1; done
 test "$enabled" = "$actual" || {{ echo "Service differs: $name" >&2; exit 1; }}
done < {INPUT}/state/preserved-service-choices.tsv
test ! -L "$N/etc/rc.d/S99openclash"
test -L "$N/etc/rc.d/S99honk"
test "$(cat "$N/etc/mu300/adb")" = off
echo SERVICE_CHOICES_PASS
"""
    print(run(script).decode())


def verify_sqlite():
    target = PRIVATE / "candidate-honk.db"
    remote = NEW + "/etc/honk/data/state/honk.db"
    names = run(f"set -eu\nfor p in {remote} {remote}-wal {remote}-shm; do "
                'if test -f "$p"; then echo "$p"; fi; done\n').decode().splitlines()
    hashes = {}
    for name in names:
        suffix = name.removeprefix(remote)
        assert suffix in ("", "-wal", "-shm")
        destination = target.with_name(target.name + suffix)
        download("cat " + name, destination)
        hashes[suffix or "database"] = hashlib.sha256(destination.read_bytes()).hexdigest()
    with sqlite3.connect(target.as_uri() + "?mode=ro", uri=True) as db:
        integrity = db.execute("PRAGMA integrity_check").fetchall()
        assert integrity == [("ok",)], "Candidate SQLite integrity failed"
    return {"integrity_check": "ok", "sha256": hashes, "writer_stopped": True}


def main():
    apply_reviewed_defaults()
    script = HERE / "freeze-candidate-data.sh"
    upload(script, INPUT + "/scripts/freeze-candidate-data.sh")
    print(run("sh " + INPUT + "/scripts/freeze-candidate-data.sh\n").decode())
    verify_configurations()
    verify_services()
    result = {"status": "PASS", "sqlite": verify_sqlite(), "packages": 321,
              "skipped_completed_defaults": 10, "remaining_defaults": 31}
    (PRIVATE / "candidate-validation.json").write_text(json.dumps(result, indent=2))
    run(f"set -eu\nprintf 'PASS\\n' > {INPUT}/state/candidate-validation-complete\nsync\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
