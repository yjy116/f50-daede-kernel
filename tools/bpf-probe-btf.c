/* SPDX-License-Identifier: GPL-2.0-only */
/* Program-local BTF for the two-function bpf_loop verifier probe.
 * This is not vmlinux BTF, and does not test CO-RE or kernel type availability.
 * Layout follows the frozen Linux bpf_loop_inline.c selftest's BTF_TYPES.
 */
#define _GNU_SOURCE
#include "bpf-probe-btf.h"
#include <linux/btf.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>

#define PROBE_BTF_STRINGS "\0int\0i\0ctx\0callback\0main"
enum {
    BTF_KIND_SHIFT = 24,
    BTF_INT_ENCODING_SHIFT = 24,
    BTF_INT_BITS = 32,
    BTF_MAIN_ARGUMENTS = 1,
    BTF_CALLBACK_ARGUMENTS = 2,
    TYPE_INT = 1, TYPE_INT_PTR, TYPE_VOID_PTR, TYPE_MAIN_PROTO,
    TYPE_CALLBACK_PROTO, TYPE_MAIN, TYPE_CALLBACK,
    NAME_INT = 1,
    NAME_INDEX = NAME_INT + sizeof("int"),
    NAME_CONTEXT = NAME_INDEX + sizeof("i"),
    NAME_CALLBACK = NAME_CONTEXT + sizeof("ctx"),
    NAME_MAIN = NAME_CALLBACK + sizeof("callback")
};

struct probe_btf_types {
    struct btf_type integer;
    __u32 integer_encoding;
    struct btf_type int_pointer, void_pointer;
    struct btf_type main_proto;
    struct btf_param main_args[BTF_MAIN_ARGUMENTS];
    struct btf_type callback_proto;
    struct btf_param callback_args[BTF_CALLBACK_ARGUMENTS];
    struct btf_type main_func, callback_func;
};

struct probe_btf_blob {
    struct btf_header header;
    struct probe_btf_types types;
    char strings[sizeof(PROBE_BTF_STRINGS)];
};

static const struct probe_btf_blob probe_btf = {
    .header = {
        .magic = BTF_MAGIC, .version = BTF_VERSION,
        .hdr_len = sizeof(struct btf_header),
        .type_len = sizeof(struct probe_btf_types),
        .str_off = sizeof(struct probe_btf_types),
        .str_len = sizeof(PROBE_BTF_STRINGS)
    },
    .types = {
        .integer = { .name_off = NAME_INT, .info = BTF_KIND_INT << BTF_KIND_SHIFT,
                     .size = sizeof(__s32) },
        .integer_encoding = (BTF_INT_SIGNED << BTF_INT_ENCODING_SHIFT) | BTF_INT_BITS,
        .int_pointer = { .info = BTF_KIND_PTR << BTF_KIND_SHIFT, .type = TYPE_INT },
        .void_pointer = { .info = BTF_KIND_PTR << BTF_KIND_SHIFT },
        .main_proto = { .info = (BTF_KIND_FUNC_PROTO << BTF_KIND_SHIFT) | BTF_MAIN_ARGUMENTS,
                        .type = TYPE_INT },
        .main_args = { { .name_off = NAME_CONTEXT, .type = TYPE_VOID_PTR } },
        .callback_proto = {
            .info = (BTF_KIND_FUNC_PROTO << BTF_KIND_SHIFT) | BTF_CALLBACK_ARGUMENTS,
            .type = TYPE_INT
        },
        .callback_args = { { .name_off = NAME_INDEX, .type = TYPE_INT },
                           { .name_off = NAME_CONTEXT, .type = TYPE_INT_PTR } },
        .main_func = { .name_off = NAME_MAIN,
                       .info = (BTF_KIND_FUNC << BTF_KIND_SHIFT) | BTF_FUNC_STATIC,
                       .type = TYPE_MAIN_PROTO },
        .callback_func = { .name_off = NAME_CALLBACK,
                           .info = (BTF_KIND_FUNC << BTF_KIND_SHIFT) | BTF_FUNC_STATIC,
                           .type = TYPE_CALLBACK_PROTO }
    },
    .strings = PROBE_BTF_STRINGS
};

/* PROG_LOAD insn_off uses instruction slots, not ELF .BTF.ext byte offsets. */
const struct bpf_func_info probe_func_info[PROBE_FUNC_COUNT] = {
    { .insn_off = PROBE_MAIN_INSN, .type_id = TYPE_MAIN },
    { .insn_off = PROBE_CALLBACK_INSN, .type_id = TYPE_CALLBACK }
};
_Static_assert(offsetof(struct probe_btf_blob, types) == sizeof(struct btf_header),
               "padding before BTF types");
_Static_assert(offsetof(struct probe_btf_blob, strings) ==
               sizeof(struct btf_header) + sizeof(struct probe_btf_types),
               "padding before BTF strings");

int load_probe_btf(char *log)
{
    union bpf_attr attr = {0};
    attr.btf = (__u64)(uintptr_t)&probe_btf;
    /* Exclude C struct tail padding from the serialized BTF payload. */
    attr.btf_size = offsetof(struct probe_btf_blob, strings) + sizeof(probe_btf.strings);
    attr.btf_log_buf = (__u64)(uintptr_t)log;
    attr.btf_log_size = PROBE_LOG_BYTES;
    attr.btf_log_level = 1;
    return (int)syscall(SYS_bpf, BPF_BTF_LOAD, &attr, sizeof(attr));
}
