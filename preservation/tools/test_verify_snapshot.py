"""Real archive/SQLite acceptance tests; run with a 60-second process timeout."""
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("verify_snapshot.py")
DB = "etc/honk/data/state/honk.db"
PRESERVE = "etc/mu300/f50-profile/preserve-paths.txt"
SECRET = "credential-value-must-never-appear"
ARCHIVES = ("settings.tar.gz", "runtime.tar.gz")


def digest(value):
    return hashlib.sha256(value).hexdigest()


class Snapshot:
    def __init__(self, root):
        self.root = root
        db = root / "fixture.db"
        with sqlite3.connect(db) as connection:
            connection.execute('CREATE TABLE "odd""name" (secret TEXT)')
            connection.execute('INSERT INTO "odd""name" VALUES (?)', (SECRET,))
        connection.close()
        self.items = {}
        self.file(DB, db.read_bytes())
        self.file("etc/config/network", SECRET.encode())
        self.file("etc/init.d/honk", b"#!/bin/sh\n", mode="0755")
        self.file("lib/modules/test/module.ko", b"module", archive=ARCHIVES[1])
        self.file(PRESERVE, b"# selected paths\netc/config/network\nlib/modules/test\netc/rc.d/S90honk\n")
        self.link("etc/rc.d/S90honk", "../init.d/honk")
        self.link("etc/resolv.conf", "/tmp/resolv.conf")
        self.metadata = {"schema_version": 1, "required_paths": [DB, PRESERVE, "lib/modules/test"],
                         "preserve_paths_file": PRESERVE, "sqlite_path": DB}

    def file(self, path, content, **options):
        self.items[path] = dict(type="file", content=content, mode="0644", uid=0, gid=0,
                                archive=ARCHIVES[0], sha256=digest(content)) | options

    def link(self, path, target):
        self.items[path] = dict(type="symlink", target=target, mode="0777", uid=0, gid=0,
                                archive=ARCHIVES[0])

    def entries(self):
        entries = dict(self.items)
        for path, item in self.items.items():
            for parent in Path(path).parents:
                name = parent.as_posix()
                if name != "." and name not in entries:
                    entries[name] = dict(type="directory", mode="0755", uid=0, gid=0,
                                         archive=item["archive"])
        return entries

    def write_tar(self, archive, entries):
        with tarfile.open(self.root / archive, "w:gz") as target:
            for path, row in entries.items():
                if row["archive"] != archive:
                    continue
                info = tarfile.TarInfo(path)
                info.mode, info.uid, info.gid = int(row["mode"], 8), row["uid"], row["gid"]
                kind = row["type"]
                info.type = {"file": tarfile.REGTYPE, "directory": tarfile.DIRTYPE,
                             "symlink": tarfile.SYMTYPE, "hardlink": tarfile.LNKTYPE}[kind]
                info.linkname = row.get("target", "")
                content = row.get("content", b"")
                info.size = len(content) if kind == "file" else 0
                target.addfile(info, io.BytesIO(content) if kind == "file" else None)

    def save(self):
        entries = self.entries()
        self.metadata["entries"] = [dict(path=path, size=len(row.get("content", b"")),
            **{k: v for k, v in row.items() if k != "content"})
            for path, row in entries.items()]
        for archive in ARCHIVES:
            self.write_tar(archive, entries)
        self.write_text("metadata.json", json.dumps(self.metadata))
        self.write_text("files.sha256", "".join(f"{digest(r['content'])}  {p}\n"
                        for p, r in entries.items() if r["type"] == "file"))
        links = [(p, r["target"]) for p, r in entries.items() if r["type"] == "symlink"]
        for name in ("links.tsv", "service-links.tsv"):
            rows = links if name == "links.tsv" else [r for r in links if r[0].startswith("etc/rc.d/")]
            self.write_text(name, "path\ttarget\n" + "".join(f"{p}\t{t}\n" for p, t in rows))
        self.write_text("packages.txt", "honk-1.0\nlibc-1.2\n")
        self.write_text("packages-world.txt", "honk\n")
        self.resign()

    def write_text(self, name, text):
        (self.root / name).write_text(text, encoding="utf-8")

    def resign(self):
        names = (*ARCHIVES, "metadata.json", "files.sha256", "links.tsv", "service-links.tsv",
                 "packages.txt", "packages-world.txt")
        self.write_text("SHA256SUMS", "".join(f"{digest((self.root / p).read_bytes())}  {p}\n" for p in names))


class VerifySnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.snapshot = Snapshot(self.root)

    def run_tool(self, *arguments):
        return subprocess.run([sys.executable, "-B", str(SCRIPT), str(self.root), *arguments],
                              capture_output=True, text=True, timeout=10)

    def rejected(self):
        result = self.run_tool()
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(result.stdout.strip().startswith("{"), result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "FAIL")
        self.assertNotIn(SECRET, result.stdout + result.stderr)

    def test_valid_snapshot_reads_sqlite_without_exposing_values(self):
        self.snapshot.save()
        before = {p.name: digest(p.read_bytes()) for p in self.root.iterdir() if p.is_file()}
        result = self.run_tool()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["sqlite"]["tables"], {"odd\"name": 1})
        self.assertIn("Windows-safe payload projection", report["materialization"])
        self.assertIn("etc/resolv.conf", report["dangling_links"])
        self.assertNotIn(SECRET, result.stdout + result.stderr)
        self.assertEqual(before, {p.name: digest(p.read_bytes()) for p in self.root.iterdir() if p.is_file()})

    def test_member_traversal_and_windows_aliases_are_rejected(self):
        for path in ("../escape", "/absolute", "a/../escape", "C:escape", "a\\escape", "//host/file"):
            with self.subTest(path=path):
                item = dict(self.snapshot.items)
                self.snapshot.file(path, b"unsafe")
                self.snapshot.save()
                self.rejected()
                self.snapshot.items = item

    def test_symlink_escape_cycles_and_ancestor_writes_are_rejected(self):
        cases = (("alias", "../../outside", None), ("alias", "alias", None),
                 ("alias", "/etc", "alias/file"), ("pivot", "/", "bad"),
                 ("alias", "etc/config/network/../target", None))
        for path, target, child in cases:
            with self.subTest(target=target):
                saved = dict(self.snapshot.items)
                self.snapshot.link(path, target)
                if child == "bad":
                    self.snapshot.link("bad", "pivot/../outside")
                if child and child != "bad":
                    self.snapshot.file(child, b"bad")
                self.snapshot.save()
                self.rejected()
                self.snapshot.items = saved

    def test_absolute_and_chained_links_resolve_inside_root(self):
        self.snapshot.link("etc/alias", "/etc/config/network")
        self.snapshot.link("etc/second", "alias")
        self.snapshot.metadata["required_paths"].append("etc/second")
        self.snapshot.link("root-link", "/")
        self.snapshot.metadata["required_paths"].append("root-link")
        self.snapshot.save()
        result = self.run_tool()
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_missing_link_ancestor_stays_dangling(self):
        self.snapshot.link("alias", "missing/../etc/config/network")
        self.snapshot.save()
        result = self.run_tool()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("alias", json.loads(result.stdout)["dangling_links"])
        self.snapshot.metadata["required_paths"].append("alias")
        self.snapshot.save()
        self.rejected()

    def test_checksums_and_metadata_mode_owner_are_enforced(self):
        self.snapshot.save()
        (self.root / "runtime.tar.gz").write_bytes(b"corruption")
        self.rejected()
        self.snapshot.save()
        (self.root / "runtime.tar.gz").write_bytes((self.root / "runtime.tar.gz").read_bytes()[:10])
        self.snapshot.resign()
        self.rejected()
        for field, value in (("mode", "0600"), ("uid", 1), ("gid", 1), ("sha256", "0" * 64)):
            with self.subTest(field=field):
                self.snapshot.save()
                meta = json.loads((self.root / "metadata.json").read_text())
                next(r for r in meta["entries"] if r["path"] == DB)[field] = value
                self.snapshot.write_text("metadata.json", json.dumps(meta))
                self.snapshot.resign()
                self.rejected()

    def test_required_preserve_and_link_lists_are_enforced(self):
        self.snapshot.metadata["required_paths"].append("not/backed/up")
        self.snapshot.save()
        self.rejected()
        self.snapshot.metadata["required_paths"].pop()
        self.snapshot.save()
        result = self.run_tool("--required-path", "not/backed/up")
        self.assertNotEqual(result.returncode, 0)
        for name, text in (("links.tsv", "path\ttarget\n"), ("service-links.tsv", "path\ttarget\n"),
                           ("files.sha256", ""), ("packages.txt", "same\nsame\n")):
            self.snapshot.save()
            self.snapshot.write_text(name, text)
            self.snapshot.resign()
            self.rejected()
        self.snapshot.file(PRESERVE, b"not/backed/up\n")
        self.snapshot.save()
        self.rejected()

    def test_database_corruption_is_rejected_even_with_matching_hashes(self):
        self.snapshot.file(DB, b"corrupt SQLite database")
        self.snapshot.save()
        self.rejected()

    def test_committed_wal_is_read_and_original_files_are_unchanged(self):
        live = self.root / "wal-source.db"
        connection = sqlite3.connect(live)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA wal_autocheckpoint=0")
        connection.execute("CREATE TABLE pending (value TEXT)")
        connection.execute("INSERT INTO pending VALUES (?)", (SECRET,))
        connection.commit()
        for suffix in ("", "-wal", "-shm"):
            self.snapshot.file(DB + suffix, Path(str(live) + suffix).read_bytes())
        self.snapshot.save()
        result = self.run_tool()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(json.loads(result.stdout)["sqlite"]["tables"], {"pending": 1})

    def test_case_distinct_linux_files_are_individually_verified(self):
        paths = ("lib/modules/test/xt_DSCP.ko", "lib/modules/test/xt_dscp.ko", "etc/CON")
        for path in paths:
            self.snapshot.file(path, path.encode())
        self.snapshot.save()
        result = self.run_tool()
        self.assertEqual(result.returncode, 0, result.stdout)
        for path in paths:
            self.snapshot.save()
            content = self.snapshot.items[path]["content"]
            self.snapshot.items[path]["content"] = bytes([content[0] ^ 1]) + content[1:]
            self.snapshot.write_tar(ARCHIVES[0], self.snapshot.entries())
            self.snapshot.resign()
            self.rejected()
            self.snapshot.items[path]["content"] = content

    def test_hardlinks_are_rejected(self):
        self.snapshot.items["alias"] = dict(type="hardlink", target=DB, mode="0644", uid=0,
                                           gid=0, archive=ARCHIVES[0])
        self.snapshot.save()
        self.rejected()

    def test_incomplete_marker_is_rejected(self):
        self.snapshot.save()
        self.snapshot.write_text("INCOMPLETE", "capture failed\n")
        self.rejected()

    def test_duplicate_tar_members_and_invalid_metadata_are_rejected(self):
        self.snapshot.save()
        archive = self.root / ARCHIVES[0]
        with tarfile.open(archive) as source:
            rows = [(r, source.extractfile(r).read() if r.isfile() else None) for r in source]
        with tarfile.open(archive, "w:gz") as target:
            for info, content in rows + rows[:1]:
                target.addfile(info, io.BytesIO(content) if content is not None else None)
        self.snapshot.resign()
        self.rejected()
        self.snapshot.save()
        self.snapshot.write_text("metadata.json", "[]")
        self.snapshot.resign()
        self.rejected()

    def test_implicit_directories_and_extra_signed_inputs_are_supported(self):
        self.snapshot.save()
        for archive in ARCHIVES:
            path = self.root / archive
            with tarfile.open(path) as source:
                rows = [(r, source.extractfile(r).read() if r.isfile() else None)
                        for r in source if not r.isdir()]
            with tarfile.open(path, "w:gz") as target:
                for info, content in rows:
                    target.addfile(info, io.BytesIO(content) if content is not None else None)
        metadata = self.snapshot.metadata
        metadata["entries"] = [r for r in metadata["entries"] if r["type"] != "directory"]
        self.snapshot.write_text("metadata.json", json.dumps(metadata))
        self.snapshot.resign()
        extra = "critical-before.sha256"
        self.snapshot.write_text(extra, "opaque independent evidence\n")
        with (self.root / "SHA256SUMS").open("a", encoding="utf-8") as stream:
            stream.write(f"{digest((self.root / extra).read_bytes())}  {extra}\n")
        result = self.run_tool()
        self.assertEqual(result.returncode, 0, result.stdout)


if __name__ == "__main__":
    unittest.main()
