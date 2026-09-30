/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef F50_BPF_PROBE_BTF_H
#define F50_BPF_PROBE_BTF_H

#include <linux/bpf.h>

enum {
    PROBE_LOG_BYTES = 256 * 1024,
    PROBE_MAIN_INSN = 0,
    PROBE_CALLBACK_INSN = 8,
    PROBE_FUNC_COUNT = 2
};

extern const struct bpf_func_info probe_func_info[PROBE_FUNC_COUNT];
/* The caller supplies PROBE_LOG_BYTES, owns the returned FD, and must close it. */
int load_probe_btf(char *log);

#endif
