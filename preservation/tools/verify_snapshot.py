"""Validate a snapshot without restoring it or revealing file contents.
metadata schema_version=1: entries contain archive/path/type/mode/uid/gid/size,
plus sha256 for files or target for symlinks. required_paths, sqlite_path and
preserve_paths_file name root-relative paths. TSV headers are path<TAB>target.
Ownership/modes are checked against tar headers; no chown or real links are used.
"""
import argparse
from contextlib import closing
import csv
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import sqlite3
import tarfile
import tempfile

ARCHIVES = ("settings.tar.gz", "runtime.tar.gz")
CONTROLS = ("metadata.json", "files.sha256", "links.tsv", "service-links.tsv",
            "packages.txt", "packages-world.txt")
COPY_BYTES = 1024 * 1024
SQLITE_SUFFIXES = ("", "-wal", "-shm")


class SnapshotError(ValueError):
    """A validation failure whose message contains no snapshot contents."""


def require(condition, message):
    if not condition:
        raise SnapshotError(message)


def path_parts(value):
    require(isinstance(value, str) and value and not re.search(r"[\\:\x00-\x1f\x7f]", value),
            "Invalid path characters")
    return value.split("/")


def relative_path(value):
    parts = path_parts(value)
    require(not value.startswith("/") and ".." not in parts, "Unsafe root-relative path")
    normalized = "/".join(p for p in parts if p not in ("", "."))
    require(bool(normalized), "Empty root-relative path")
    return normalized


def local_file(root, name):
    path = root / relative_path(name)
    require(all(not p.is_symlink() for p in (path, *path.parents) if p != root.parent),
            "Snapshot inputs must not traverse filesystem symlinks")
    require(path.is_file(), "Required snapshot input is missing")
    return path


def file_hash(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def sha_manifest(path):
    result = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([a-fA-F0-9]{64})  (.+)", line)
        require(match is not None, "Malformed SHA256 manifest")
        name = relative_path(match[2])
        require(name not in result, "Duplicate SHA256 path")
        result[name] = match[1].lower()
    return result


def verify_inputs(root):
    require(not (root / "INCOMPLETE").exists(), "Snapshot is marked INCOMPLETE")
    hashes = sha_manifest(local_file(root, "SHA256SUMS"))
    require(set(ARCHIVES + CONTROLS) <= hashes.keys(), "SHA256SUMS omits required inputs")
    for name, expected in hashes.items():
        require(file_hash(local_file(root, name)) == expected, "Snapshot input checksum mismatch")
    return json.loads(local_file(root, "metadata.json").read_text(encoding="utf-8"))


def metadata_entries(metadata):
    require(isinstance(metadata, dict), "Metadata must be a JSON object")
    require(metadata.get("schema_version") == 1, "Unsupported metadata schema")
    require(isinstance(metadata.get("entries"), list), "Metadata entries must be a list")
    entries = {}
    for row in metadata["entries"]:
        path = relative_path(row["path"])
        require(path == row["path"] and row["archive"] in ARCHIVES, "Invalid metadata location")
        require(row["type"] in ("file", "directory", "symlink"), "Unsupported metadata member type")
        require(isinstance(row["mode"], str) and re.fullmatch(r"[0-7]{3,4}", row["mode"]),
                "Invalid metadata mode")
        require(all(type(row[k]) is int and row[k] >= 0 for k in ("uid", "gid", "size")),
                "Invalid metadata numeric attributes")
        key = (row["archive"], path)
        require(key not in entries, "Duplicate metadata member")
        entries[key] = row
    return entries


def member_type(member):
    for check, kind in ((member.isfile, "file"), (member.isdir, "directory"), (member.issym, "symlink")):
        if check():
            return kind
    raise SnapshotError("Unsupported tar member type")


def archive_members(root):
    for archive in ARCHIVES:
        with tarfile.open(local_file(root, archive), "r:gz") as source:
            for member in source:
                yield archive, source, member


def read_members(root, entries):
    members, seen = {}, set()
    for archive, _, member in archive_members(root):
        path = relative_path(member.name)
        key = (archive, path)
        require(key in entries and key not in seen, "Unexpected or duplicate tar member")
        row = entries[key]
        actual = (member_type(member), member.mode, member.uid, member.gid, member.size)
        expected = (row["type"], int(row["mode"], 8), row["uid"], row["gid"], row["size"])
        require(actual == expected, "Tar metadata mismatch")
        if member.issym():
            require(member.linkname == row["target"], "Tar link target mismatch")
        if path in members:
            prior = members[path]
            require(row["type"] == "directory" and all(prior[k] == row[k]
                    for k in ("type", "mode", "uid", "gid", "size")), "Conflicting archive paths")
        members[path] = row
        seen.add(key)
    require(seen == entries.keys(), "Metadata member missing from archives")
    return members


def resolve_parts(parts, context, trail=frozenset()):
    members, present = context
    resolved, exists = [], True
    for part in parts:
        exists = exists and "/".join(resolved) in present
        require(members.get("/".join(resolved), {}).get("type") != "file",
                "Link traverses a non-directory")
        if part in ("", "."):
            continue
        if part == "..":
            require(bool(resolved), "Symlink escapes simulated root")
            resolved.pop()
            continue
        resolved.append(part)
        path = "/".join(resolved)
        row = members.get(path, {})
        if row.get("type") == "symlink":
            require(path not in trail, "Symlink cycle")
            target = row["target"]
            base = [] if target.startswith("/") else resolved[:-1]
            resolved, target_exists = resolve_parts(base + path_parts(target), context, trail | {path})
            exists = exists and target_exists
    return resolved, exists and "/".join(resolved) in present


def validate_tree(members):
    present = set(members) | {""}
    for path in members:
        parents = [str(p) for p in PurePosixPath(path).parents if str(p) != "."]
        for parent in parents:
            require(members.get(parent, {}).get("type", "directory") == "directory",
                    "Archive member has a non-directory ancestor")
        present.update(parents)
    for path, row in members.items():
        if row["type"] == "symlink":
            resolve_parts(path_parts(path), (members, present))
    return present


def link_manifest(path):
    with path.open(encoding="utf-8", newline="") as stream:
        rows = csv.reader(stream, delimiter="\t")
        require(next(rows, None) == ["path", "target"], "Malformed link manifest header")
        result = {}
        for row in rows:
            require(len(row) == 2, "Malformed link manifest row")
            name = relative_path(row[0])
            require(name not in result, "Duplicate link manifest path")
            result[name] = row[1]
        return result


def verify_manifests(root, members):
    files = {p: r["sha256"] for p, r in members.items() if r["type"] == "file"}
    require(sha_manifest(root / "files.sha256") == files, "File manifest differs from metadata")
    links = {p: r["target"] for p, r in members.items() if r["type"] == "symlink"}
    require(link_manifest(root / "links.tsv") == links, "Link manifest differs from metadata")
    services = {p: t for p, t in links.items() if p.startswith("etc/rc.d/")}
    require(link_manifest(root / "service-links.tsv") == services, "Service link manifest mismatch")
    for name in ("packages.txt", "packages-world.txt"):
        rows = (root / name).read_text(encoding="utf-8").splitlines()
        require(rows and all(r and r == r.strip() for r in rows) and len(set(rows)) == len(rows),
                "Package list is empty, malformed or duplicated")


def projected_path(temporary, path):
    return temporary / hashlib.sha256(path.encode("utf-8")).hexdigest()


def materialize(root, temporary, members):
    for _, source, member in archive_members(root):
        path = relative_path(member.name)
        destination = projected_path(temporary, path)
        if member.isfile():
            with source.extractfile(member) as src, destination.open("xb") as dst:
                shutil.copyfileobj(src, dst, COPY_BYTES)
            require(file_hash(destination) == members[path]["sha256"], "Archived file checksum mismatch")


def required_target(path, members, present):
    resolved, exists = resolve_parts(path_parts(relative_path(path)), (members, present))
    require(exists, "Required path is not present in snapshot")
    return "/".join(resolved)


def verify_required(metadata, context, extra):
    members, present, temporary = context
    required = metadata.get("required_paths")
    require(isinstance(required, list) and required, "required_paths must be a nonempty list")
    for path in required + list(extra):
        required_target(path, members, present)
    preserve = required_target(metadata["preserve_paths_file"], members, present)
    require(members[preserve]["type"] == "file", "Preserve manifest is not a regular file")
    for line in projected_path(temporary, preserve).read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            required_target(line, members, present)
    return required_target(metadata["sqlite_path"], members, present)


def sqlite_projection(database, members, temporary):
    destination = temporary / "sqlite"
    destination.mkdir()
    for suffix in SQLITE_SUFFIXES:
        path = database + suffix
        if suffix and path not in members:
            continue
        require(members.get(path, {}).get("type") == "file", "SQLite member is not a regular file")
        projected = destination / ("snapshot.db" + suffix)
        shutil.copyfile(projected_path(temporary, path), projected)
        require(file_hash(projected) == members[path]["sha256"], "SQLite projection checksum mismatch")
    return destination / "snapshot.db"


def verify_sqlite(path):
    require(path.is_file(), "SQLite database is not a regular file")
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as connection:
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        require(connection.execute("PRAGMA integrity_check").fetchall() == [("ok",)],
                "SQLite integrity_check failed")
        tables = {}
        for (name,) in connection.execute("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name"):
            # SQLite identifiers cannot be bound; double-quote escaping is required.
            identifier = '"' + name.replace('"', '""') + '"'
            tables[name] = connection.execute("SELECT count(*) FROM " + identifier).fetchone()[0]
    return {"integrity_check": "ok", "tables": tables}


def verify_snapshot(directory, required_paths=()):
    root = Path(directory).resolve()
    metadata = verify_inputs(root)
    members = read_members(root, metadata_entries(metadata))
    present = validate_tree(members)
    verify_manifests(root, members)
    with tempfile.TemporaryDirectory(prefix="f50-verify-") as temporary:
        temporary = Path(temporary)
        materialize(root, temporary, members)
        database = verify_required(metadata, (members, present, temporary), required_paths)
        sqlite = verify_sqlite(sqlite_projection(database, members, temporary))
    dangling = [p for p, r in members.items() if r["type"] == "symlink"
                and not resolve_parts(path_parts(p), (members, present))[1]]
    return {"status": "PASS", "members": len(members), "sqlite": sqlite,
            "dangling_links": sorted(dangling), "attributes_checked": "tar headers; no chown",
            "materialization": "Windows-safe payload projection; POSIX paths preserved virtually"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot_directory")
    parser.add_argument("--required-path", action="append", default=[])
    args = parser.parse_args()
    try:
        result = verify_snapshot(args.snapshot_directory, args.required_path)
    except (ValueError, TypeError, KeyError, OSError, EOFError, tarfile.TarError, sqlite3.Error, RecursionError) as error:
        message = str(error) if isinstance(error, SnapshotError) else type(error).__name__
        print(json.dumps({"status": "FAIL", "error": message}))
        return 1
    print(json.dumps(result, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
