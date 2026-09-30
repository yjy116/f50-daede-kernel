"""Resolve promoted skb checksum bits from the matching kernel's raw BTF."""
import json
import struct

from validate_kernel import file_record, require

HEADER = struct.Struct('<HBBIIIII')
TYPE = struct.Struct('<III')
BYTE_BITS = 8
CHECKSUM_BITS = 2
BTF_MAGIC, BTF_VERSION, BTF_FLAGS = 0xeb9f, 1, 0
KIND_SHIFT, KIND_MASK = 24, 31
KIND_FLAG_SHIFT = 31
VLEN_MASK = (1 << 16) - 1
MEMBER_WIDTH_SHIFT = 24
MEMBER_OFFSET_MASK = (1 << MEMBER_WIDTH_SHIFT) - 1
STRUCT_KIND, UNION_KIND = 4, 5
STRUCT_KINDS = (STRUCT_KIND, UNION_KIND)
MODIFIER_KINDS = (8, 9, 10, 11, 18)
FIXED_PAYLOAD = {1: 4, 2: 0, 3: 12, 7: 0, 8: 0, 9: 0, 10: 0,
                 11: 0, 12: 0, 14: 4, 16: 0, 17: 4, 18: 0}
VARIABLE_PAYLOAD = {4: 12, 5: 12, 6: 8, 13: 8, 15: 12, 19: 12}


def string_at(strings, offset):
    end = strings.find(b'\0', offset)
    require(0 <= offset <= end < len(strings), 'Invalid BTF string offset')
    return strings[offset:end].decode('utf-8')


def parse_types(data):
    require(len(data) >= HEADER.size, 'Truncated BTF header')
    magic, version, flags, size, start, length, names, names_length = HEADER.unpack_from(data)
    require((magic, version, flags) == (BTF_MAGIC, BTF_VERSION, BTF_FLAGS), 'Invalid raw BTF header')
    require(size >= HEADER.size and start == 0 and names == length, 'Invalid BTF ranges')
    require(size + names + names_length == len(data), 'Truncated or trailing BTF bytes')
    strings = data[size + names:]
    require(strings[:1] == strings[-1:] == b'\0', 'Invalid BTF string table')
    offset, end, types = size, size + length, [None]
    while offset < end:
        require(offset + TYPE.size <= end, 'Truncated BTF type')
        name, info, target = TYPE.unpack_from(data, offset)
        kind, count = (info >> KIND_SHIFT) & KIND_MASK, info & VLEN_MASK
        require(kind in FIXED_PAYLOAD or kind in VARIABLE_PAYLOAD, 'Unknown BTF kind')
        payload_size = FIXED_PAYLOAD.get(kind, VARIABLE_PAYLOAD.get(kind, 0) * count)
        next_offset = offset + TYPE.size + payload_size
        require(next_offset <= end, 'Truncated BTF payload')
        types.append(dict(name=string_at(strings, name), kind=kind, count=count,
                          target=target, flag=info >> KIND_FLAG_SHIFT,
                          payload=data[offset + TYPE.size:next_offset]))
        offset = next_offset
    return types, strings


def unwrap_type(types, type_id):
    seen = set()
    while True:
        require(0 < type_id < len(types) and type_id not in seen, 'Invalid/cyclic BTF type')
        seen.add(type_id)
        entry = types[type_id]
        if entry['kind'] not in MODIFIER_KINDS:
            return type_id
        type_id = entry['target']


def find_promoted(context, type_id, *, base=0, ancestors=()):
    types, strings = context
    type_id = unwrap_type(types, type_id)
    require(type_id not in ancestors, 'Cyclic BTF member type')
    entry = types[type_id]
    require(entry['kind'] in STRUCT_KINDS, 'Anonymous member is not a struct/union')
    found = []
    for index in range(entry['count']):
        name, target, encoded = TYPE.unpack_from(entry['payload'], index * TYPE.size)
        require(0 < target < len(types), 'Invalid BTF member target')
        member = string_at(strings, name)
        offset = encoded & MEMBER_OFFSET_MASK if entry['flag'] else encoded
        width = encoded >> MEMBER_WIDTH_SHIFT if entry['flag'] else 0
        require(offset + width <= entry['target'] * BYTE_BITS, 'BTF member exceeds container')
        if member == 'ip_summed':
            require(width == CHECKSUM_BITS, 'Expected two-bit skb checksum field')
            found.append(base + offset)
        if member:
            continue
        target = unwrap_type(types, target)
        require(types[target]['kind'] in STRUCT_KINDS, 'Anonymous member is not a struct/union')
        require(offset + types[target]['target'] * BYTE_BITS <= entry['target'] * BYTE_BITS,
                'Anonymous BTF member exceeds container')
        found.extend(find_promoted(context, target, base=base + offset,
                                   ancestors=ancestors + (type_id,)))
    return found


def checksum_field(data):
    context = parse_types(data)
    matches = [index for index, entry in enumerate(context[0]) if entry and
               entry['kind'] == STRUCT_KIND and entry['name'] == 'sk_buff']
    require(len(matches) == 1, 'Expected one raw BTF sk_buff definition')
    positions = find_promoted(context, matches[0])
    require(len(positions) == 1, 'Expected one promoted raw BTF checksum member')
    offset, bit = divmod(positions[0], BYTE_BITS)
    require(bit + CHECKSUM_BITS <= BYTE_BITS, 'Raw BTF checksum field crosses a byte')
    return offset, bit


def require_record(path, expected):
    actual = file_record(path)
    require(all(actual[key] == expected[key] for key in ('size', 'sha256')),
            'Kernel/BTF bytes differ from kernel validation: ' + str(path))
    return actual


def verified_layout(kernel, directory):
    evidence = json.loads((directory / 'kernel-validation.json').read_text())
    require(evidence['status'] == 'PASS', 'Kernel validation failed before WLAN BTF check')
    kernels = [row for row in evidence['artifacts'] if row['path'].endswith('/vmlinux')]
    require(len(kernels) == 1, 'Ambiguous validated kernel image')
    require_record(kernel, kernels[0])
    btf = directory / 'vmlinux.btf'
    record = require_record(btf, evidence['kernel']['detached_btf'])
    offset, bit = checksum_field(btf.read_bytes())
    return {'btf': record, 'byte_offset': offset, 'bit_offset': bit}
