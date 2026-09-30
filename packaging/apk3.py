"""Read the pinned APK3 schema without executing its payload or lifecycle scripts."""
import hashlib
import struct
import zlib
from pathlib import PurePosixPath

ALIGNMENT = 8
VALUE_SHIFT, VALUE_MASK = 28, 0x0fffffff
BLOCK_SHIFT, BLOCK_MASK = 30, 0x3fffffff
SYMLINK_TYPE = 0xa000
TARGET_TYPE_BYTES = 2
INFO_FIELDS = ('name version hashes description arch license origin maintainer url '
               'repo-commit build-time installed-size file-size provider-priority '
               'depends provides replaces install-if recommends layer tags').split()
SCRIPT_FIELDS = ('trigger pre-install post-install pre-deinstall post-deinstall '
                 'pre-upgrade post-upgrade').split()
DEPENDENCY_FIELDS = {'depends', 'provides', 'replaces', 'install-if', 'recommends'}
LIST_FIELDS = DEPENDENCY_FIELDS | {'tags'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def field(values, index):
    return values[index] if values and index < len(values) else None


def read_range(data, offset, size):
    require(offset >= 0 and size >= 0 and offset + size <= len(data), 'Truncated APK3 range')
    return data[offset:offset + size]


def u32(data, offset):
    return int.from_bytes(read_range(data, offset, 4), 'little')


def decode(data, value, ancestors=frozenset()):
    kind, offset = value >> VALUE_SHIFT, value & VALUE_MASK
    if kind == 0:
        return None
    if kind == 1:
        return offset
    if kind in (2, 3):
        return int.from_bytes(read_range(data, offset, 4 if kind == 2 else 8), 'little')
    if kind in (8, 9, 10):
        width = 1 << (kind - 8)
        length = int.from_bytes(read_range(data, offset, width), 'little')
        return read_range(data, offset + width, length)
    require(kind in (13, 14), f'Unsupported APK3 value type {kind}')
    require(offset not in ancestors, 'Cyclic APK3 metadata')
    count = u32(data, offset)
    require(count > 0, 'Empty APK3 array encoding')
    read_range(data, offset, count * 4)
    return [None] + [decode(data, u32(data, offset + i * 4), ancestors | {offset})
                     for i in range(1, count)]


def blocks(raw):
    require(raw[:ALIGNMENT] == b'ADB.pckg', 'Not an APK3 package')
    offset = ALIGNMENT
    while offset < len(raw):
        value = u32(raw, offset)
        kind, size = value >> BLOCK_SHIFT, value & BLOCK_MASK
        require(kind != 3 and size >= 4, 'Unsupported extended/invalid APK3 block')
        yield kind, read_range(raw, offset + 4, size - 4)
        offset += (size + ALIGNMENT - 1) // ALIGNMENT * ALIGNMENT
    require(offset == len(raw), 'Invalid APK3 trailing alignment')


def text(value):
    return value.decode('utf-8') if value is not None else None


def dependency(value):
    require(field(value, 3) in (None, 0), 'Unsupported dependency operator in pinned input')
    name, version = text(field(value, 1)), text(field(value, 2))
    require(bool(name), 'Empty APK dependency name')
    return name + ('=' + version if version else '')


def tags(value):
    require(isinstance(value, list) and value and value[0] is None, 'Invalid tags array')
    require(all(isinstance(row, bytes) for row in value[1:]), 'Invalid tags element')
    result = [text(row) for row in value[1:]]
    require(all(row and not any(c.isspace() or c == '\0' for c in row) for row in result),
            'Tags cannot round-trip through apk token syntax')
    return result


def info_values(values):
    result = {}
    require(len(values) <= len(INFO_FIELDS) + 1, 'Unknown package info fields')
    for index, name in enumerate(INFO_FIELDS, 1):
        value = field(values, index)
        if value is None:
            continue
        if name in DEPENDENCY_FIELDS:
            value = [dependency(row) for row in value[1:]]
        elif name == 'tags':
            value = tags(value)
        elif name in ('hashes', 'repo-commit'):
            value = value.hex()
        elif isinstance(value, bytes):
            value = text(value)
        require(name in LIST_FIELDS or not isinstance(value, list),
                f'Unsupported structured info field {name}')
        result[name] = value
    return result


def safe_path(name, root=False):
    if root and name == '':
        return name
    parts = name.split('/')
    require(name and not PurePosixPath(name).is_absolute(), 'Absolute/empty APK path')
    require(all(part not in ('', '.', '..') for part in parts), 'Noncanonical APK path')
    require('\\' not in name and '\0' not in name, 'Invalid APK path character')
    return name


def acl(values):
    require(field(values, 4) is None and len(values) <= 5, 'Unexpected xattrs in pinned package')
    result = {'mode': field(values, 1), 'user': text(field(values, 2)),
              'group': text(field(values, 3))}
    require(isinstance(result['mode'], int), 'Missing mode')
    require(result['user'] == result['group'] == 'root', 'Unexpected non-root ownership')
    return result


def member_record(member):
    require(len(member) <= 7, 'Unknown file metadata fields')
    result = dict(acl(field(member, 2)), size=field(member, 3), mtime=field(member, 4))
    digest, target = field(member, 5), field(member, 6)
    if target is None:
        require(isinstance(digest, bytes) and len(digest) == 32, 'Invalid regular-file SHA256')
        return dict(result, type='regular', sha256=digest.hex())
    require(len(target) > TARGET_TYPE_BYTES, 'Truncated link target')
    require(int.from_bytes(target[:TARGET_TYPE_BYTES], 'little') == SYMLINK_TYPE,
            'Unsupported device/hardlink target type')
    require(digest is None, 'Unexpected payload hash on symlink')
    link_bytes = target[TARGET_TYPE_BYTES:]
    require(len(link_bytes) == result['size'], 'Symlink target length mismatch')
    link_target = safe_path(text(link_bytes))
    return dict(result, type='symlink', target=link_target, target_blob_hex=target.hex())


def directory_records(paths):
    directories, files, locations = {}, {}, {}
    for directory_index, row in enumerate(paths[1:], 1):
        require(len(row) <= 4, 'Unknown directory metadata fields')
        name = safe_path(text(field(row, 1)) or '', root=True)
        require(name not in directories, f'Duplicate directory {name}')
        directories[name] = acl(field(row, 2))
        for file_index, member in enumerate((field(row, 3) or [None])[1:], 1):
            leaf = safe_path(text(field(member, 1)))
            require('/' not in leaf, 'File entry is not a basename')
            path = safe_path('/'.join(filter(None, (name, leaf))))
            require(path not in files, f'Duplicate file {path}')
            files[path] = member_record(member)
            locations[(directory_index, file_index)] = path
    require(not set(directories) & set(files), 'File/directory path collision')
    return directories, files, locations


def verify_data(chunks, records):
    files, locations = records
    seen, selected = set(), {}
    for kind, body in chunks:
        if kind != 2:
            continue
        key = struct.unpack('<II', read_range(body, 0, ALIGNMENT))
        require(key in locations, 'Data block references nonexistent member')
        name = locations[key]
        require(files[name]['type'] == 'regular', f'Unexpected payload block for link {name}')
        require(name not in seen, f'Duplicate data for {name}')
        content = body[ALIGNMENT:]
        require(len(content) == files[name]['size'], f'Size mismatch for {name}')
        require(hashlib.sha256(content).hexdigest() == files[name]['sha256'],
                f'Payload SHA256 mismatch for {name}')
        seen.add(name)
        if name == 'etc/config/daed':
            selected[name] = content
    regular = {name for name, record in files.items() if record['type'] == 'regular'}
    require(seen == regular, 'Missing payload data block')
    return selected


def read_package(path):
    packed = path.read_bytes()
    require(packed[:4] == b'ADBd', 'Expected APK3 legacy deflate compression (deflate:0)')
    decompressor = zlib.decompressobj(-15)
    raw = decompressor.decompress(packed[4:]) + decompressor.flush()
    require(decompressor.eof and not decompressor.unused_data, 'Incomplete/trailing APK compression')
    chunks = list(blocks(raw))
    require(chunks and chunks[0][0] == 0, 'Missing leading ADB metadata')
    require(sum(kind == 0 for kind, _ in chunks) == 1, 'Multiple APK metadata blocks')
    adb = chunks[0][1]
    package = decode(adb, u32(adb, 4))
    require(len(package) <= 6, 'Unknown package fields')
    directories, files, locations = directory_records(package[2])
    selected = verify_data(chunks, (files, locations))
    require(len(field(package, 3) or []) <= len(SCRIPT_FIELDS) + 1, 'Unknown script types')
    scripts = {name: field(field(package, 3), index)
               for index, name in enumerate(SCRIPT_FIELDS, 1)
               if field(field(package, 3), index) is not None}
    require(not any(field(package, i) for i in (4, 5)), 'Unexpected triggers/replaces-priority')
    return {'info': info_values(package[1]), 'directories': directories, 'files': files,
            'scripts': scripts, 'selected_contents': selected, 'package_fields': {},
            'signature_blocks': sum(kind == 1 for kind, _ in chunks),
            'apk_sha256': hashlib.sha256(packed).hexdigest(), 'apk_size': len(packed)}
