"""Fail closed if signing changes anything except the APK signature/container."""
import hashlib
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'packaging'))
from apk3 import ALIGNMENT, BLOCK_MASK, BLOCK_SHIFT, read_range, require, u32

OUTER_FIELDS = {'apk_sha256', 'apk_size', 'signature_blocks'}


def audit_models(source, signed):
    require(source['signature_blocks'] == 0, 'Pinned input must be unsigned')
    require(signed['signature_blocks'] == 1, 'Exactly one signature is required')
    require(set(source) == set(signed), 'APK parser field set changed')
    for name in set(source) - OUTER_FIELDS:
        require(source[name] == signed[name], f'Signing changed APK {name}')


def unsigned_blocks(packed):
    require(packed[:4] == b'ADBd', 'Expected APK3 deflate:0 input/output')
    decoder = zlib.decompressobj(-15)
    raw = decoder.decompress(packed[4:]) + decoder.flush()
    require(decoder.eof and not decoder.unused_data, 'Truncated/trailing compression')
    require(raw[:ALIGNMENT] == b'ADB.pckg', 'Expected APK package schema')
    result, offset = bytearray(raw[:ALIGNMENT]), ALIGNMENT
    while offset < len(raw):
        value = u32(raw, offset)
        kind, size = value >> BLOCK_SHIFT, value & BLOCK_MASK
        require(kind != 3 and size >= 4, 'Invalid/unsupported APK block')
        aligned_size = (size + ALIGNMENT - 1) // ALIGNMENT * ALIGNMENT
        chunk = read_range(raw, offset, aligned_size)
        if kind != 1:
            result.extend(chunk)
        offset += aligned_size
    require(offset == len(raw), 'Invalid APK block alignment')
    return bytes(result)


def json_record(value):
    if isinstance(value, bytes):
        return {'sha256': hashlib.sha256(value).hexdigest(), 'size': len(value)}
    if isinstance(value, dict):
        return {key: json_record(item) for key, item in value.items()}
    if isinstance(value, list):
        return [json_record(item) for item in value]
    return value
