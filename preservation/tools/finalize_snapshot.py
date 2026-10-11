"""Remove the task authorization and describe the captured, private snapshot."""
import argparse
import hashlib
import io
import json
import shutil
import tarfile
from pathlib import Path, PurePosixPath

AUTH_PATH = "etc/dropbear/authorized_keys"
KERNEL_SHA = "38d90b05c5595fa4c2fc0843808a1f850322018eaa1eb5e650e4e8c33d259bd9"
ARCHIVES = ("settings.tar.gz", "runtime.tar.gz")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def archive_path(name):
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("Unsafe archive path")
    return path.as_posix().removeprefix("./")


def sanitize_authorization(snapshot, public_key):
    source = snapshot / ARCHIVES[0]
    output = snapshot / "settings.sanitized.tar.gz"
    key = public_key.read_bytes().strip()
    assert key.endswith(b" f50-config-freeze-20261011")
    removed = 0
    unchanged = {}
    with tarfile.open(source) as old, tarfile.open(output, "w:gz") as new:
        for member in old:
            stream = old.extractfile(member) if member.isfile() else None
            if archive_path(member.name) == AUTH_PATH:
                data = stream.read()
                lines = data.splitlines(keepends=True)
                removed = sum(line.strip() == key for line in lines)
                assert removed == 1, "Expected exactly one task authorization"
                data = b"".join(line for line in lines if line.strip() != key)
                member.size = len(data)
                stream = io.BytesIO(data)
            elif member.isfile():
                data = stream.read()
                unchanged[member.name] = digest(data)
                stream = io.BytesIO(data)
            new.addfile(member, stream)
    assert removed == 1
    with tarfile.open(output) as verified:
        for member in verified:
            if member.name in unchanged:
                assert digest(verified.extractfile(member).read()) == unchanged[member.name]
            if archive_path(member.name) == AUTH_PATH:
                assert key not in verified.extractfile(member).read()
    output.replace(source)
    return {"removed_task_keys": removed, "other_regular_files_verified": len(unchanged)}


def describe_archive(snapshot, name):
    entries = []
    with tarfile.open(snapshot / name) as archive:
        for member in archive:
            kind = "file" if member.isfile() else "symlink" if member.issym() else "directory"
            assert member.isfile() or member.issym() or member.isdir()
            entry = dict(archive=name, path=archive_path(member.name), type=kind,
                         mode=f"{member.mode:04o}", uid=member.uid, gid=member.gid,
                         size=member.size)
            if member.isfile():
                entry["sha256"] = digest(archive.extractfile(member).read())
            if member.issym():
                entry["target"] = member.linkname
            entries.append(entry)
    return entries


def write_metadata(snapshot, sanitation):
    entries = [entry for name in ARCHIVES for entry in describe_archive(snapshot, name)]
    assert len({item["path"] for item in entries}) == len(entries)
    required = [line for line in (snapshot / "preserve-paths.txt").read_text().splitlines()
                if line and not line.startswith("#")]
    metadata = dict(schema_version=1, entries=entries, required_paths=required,
                    preserve_paths_file="etc/mu300/f50-profile/preserve-paths.txt",
                    sqlite_path="etc/honk/data/state/honk.db", sanitation=sanitation,
                    image=(snapshot / "image-version.txt").read_text().strip(),
                    kernel=(snapshot / "kernel.txt").read_text().strip())
    (snapshot / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8", newline="\n")
    files = [e for e in entries if e["type"] == "file"]
    links = [e for e in entries if e["type"] == "symlink"]
    (snapshot / "files.sha256").write_text(
        "".join(f"{e['sha256']}  {e['path']}\n" for e in files), encoding="utf-8", newline="\n")
    (snapshot / "links.tsv").write_text(
        "path\ttarget\n" + "".join(f"{e['path']}\t{e['target']}\n" for e in links), encoding="utf-8", newline="\n")


def finalize(options):
    snapshot = options.snapshot.resolve()
    assert not (snapshot / "metadata.json").exists(), "Snapshot already finalized"
    for line in (snapshot / "device-archives.sha256").read_text().splitlines():
        expected, name = line.split(maxsplit=1)
        assert digest((snapshot / name).read_bytes()) == expected
    sanitation = sanitize_authorization(snapshot, options.public_key)
    assert digest(options.kernel.read_bytes()) == KERNEL_SHA
    shutil.copy2(options.kernel, snapshot / options.kernel.name)
    write_metadata(snapshot, sanitation)
    hashes = [f"{digest(path.read_bytes())}  {path.name}\n"
              for path in sorted(snapshot.iterdir()) if path.is_file() and path.name != "SHA256SUMS"]
    (snapshot / "SHA256SUMS").write_text("".join(hashes), encoding="utf-8", newline="\n")
    print(json.dumps({"finalized": str(snapshot), "sanitation": sanitation,
                      "hashed_artifacts": len(hashes)}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--kernel", type=Path, required=True)
    finalize(parser.parse_args())
