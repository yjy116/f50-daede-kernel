/* SPDX-License-Identifier: GPL-2.0-only */
/* Native ARM64: gcc -std=c11 -O2 -Wall -Wextra -Werror -static
 *              bpf-probe.c bpf-probe-btf.c -o bpf-probe
 * Only BTF_LOAD / PROG_LOAD / GET_INFO / CLOSE. No execution, attach, map or pin.
 * PASS proves these small programs load and JIT, not CO-RE or full dae readiness.
 */
#define _GNU_SOURCE
#include "bpf-probe-btf.h"
#include <errno.h>
#include <linux/bpf.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define ARRAY_COUNT(array) (sizeof(array) / sizeof((array)[0]))
#define MOV64(dst, value) \
    { .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = (dst), .imm = (value) }
#define EXIT_INSN { .code = BPF_JMP | BPF_EXIT }

enum {
    LOOP_ITERATIONS = 1,
    LOOP_FUNC_INSN = 1,
    LOOP_INSN_COUNT = 10,
    LOOP_FUNC_RELATIVE = PROBE_CALLBACK_INSN - LOOP_FUNC_INSN - 1,
    TC_RESULT_OK = 0,
    CGROUP_ALLOW = 1
};

/* LD_IMM64 uses two slots. PSEUDO_FUNC target = first-slot index + imm + 1.
 * Callback at slot 8 returns 0 (continue); NULL callback_ctx is supported.
 * The helper would return the iteration count, not zero. It is never executed
 * here; the main program replaces r0 with its program-type-appropriate result.
 */
#define LOOP_PROGRAM(result) \
    MOV64(BPF_REG_1, LOOP_ITERATIONS), \
    { .code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_2, \
      .src_reg = BPF_PSEUDO_FUNC, .imm = LOOP_FUNC_RELATIVE }, \
    { .code = 0 }, \
    MOV64(BPF_REG_3, 0), \
    MOV64(BPF_REG_4, 0), \
    { .code = BPF_JMP | BPF_CALL, .imm = BPF_FUNC_loop }, \
    MOV64(BPF_REG_0, (result)), \
    EXIT_INSN, \
    MOV64(BPF_REG_0, 0), \
    EXIT_INSN

static const struct bpf_insn tc_program[] = {
    MOV64(BPF_REG_0, TC_RESULT_OK), EXIT_INSN
};
static const struct bpf_insn cgroup_program[] = {
    MOV64(BPF_REG_0, CGROUP_ALLOW), EXIT_INSN
};
static const struct bpf_insn tc_loop_program[] = {
    LOOP_PROGRAM(TC_RESULT_OK)
};
static const struct bpf_insn cgroup_loop_program[] = {
    LOOP_PROGRAM(CGROUP_ALLOW)
};
_Static_assert(sizeof(struct bpf_insn) == 8, "unexpected BPF instruction ABI");
_Static_assert(ARRAY_COUNT(tc_loop_program) == LOOP_INSN_COUNT, "loop layout changed");
_Static_assert(ARRAY_COUNT(cgroup_loop_program) == LOOP_INSN_COUNT, "loop layout changed");

struct probe {
    const char *name;
    enum bpf_prog_type type;
    enum bpf_attach_type attach_type;
    const struct bpf_insn *instructions;
    size_t count;
    bool needs_btf;
};

static const struct probe probes[] = {
    { "sched_cls", BPF_PROG_TYPE_SCHED_CLS, 0,
      tc_program, ARRAY_COUNT(tc_program), false },
    { "cgroup_sock", BPF_PROG_TYPE_CGROUP_SOCK, BPF_CGROUP_INET_SOCK_CREATE,
      cgroup_program, ARRAY_COUNT(cgroup_program), false },
    { "cgroup_sock_addr", BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_INET4_CONNECT,
      cgroup_program, ARRAY_COUNT(cgroup_program), false },
    { "sched_cls_loop", BPF_PROG_TYPE_SCHED_CLS, 0,
      tc_loop_program, ARRAY_COUNT(tc_loop_program), true },
    { "cgroup_sock_addr_loop", BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_INET4_CONNECT,
      cgroup_loop_program, ARRAY_COUNT(cgroup_loop_program), true }
};

struct inspection {
    struct bpf_prog_info info;
    __u32 returned_bytes;
    int error;
};

static int report_error(const struct probe *probe, const char *stage, int error)
{
    printf("probe=%s status=FAIL stage=%s errno=%d\n", probe->name, stage, error);
    fprintf(stderr, "%s: %s: %s (errno=%d)\n",
            probe->name, stage, strerror(error), error);
    return 1;
}

static int load_program(const struct probe *probe, char *log, int btf_fd)
{
    static const char license[] = "GPL";
    union bpf_attr attr = {0};
    attr.prog_type = probe->type;
    attr.expected_attach_type = probe->attach_type;
    attr.insn_cnt = (__u32)probe->count;
    attr.insns = (__u64)(uintptr_t)probe->instructions;
    attr.license = (__u64)(uintptr_t)license;
    attr.log_buf = (__u64)(uintptr_t)log;
    attr.log_size = PROBE_LOG_BYTES;
    attr.log_level = 1;
    if (probe->needs_btf) {
        attr.prog_btf_fd = (__u32)btf_fd;
        attr.func_info = (__u64)(uintptr_t)probe_func_info;
        attr.func_info_cnt = PROBE_FUNC_COUNT;
        attr.func_info_rec_size = sizeof(probe_func_info[0]);
    }
    return (int)syscall(SYS_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
}

static struct inspection inspect_program(int fd)
{
    struct inspection result = {0};
    union bpf_attr attr = {0};
    attr.info.bpf_fd = (__u32)fd;
    attr.info.info_len = sizeof(result.info);
    attr.info.info = (__u64)(uintptr_t)&result.info;
    if (syscall(SYS_bpf, BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) != 0)
        result.error = errno;
    result.returned_bytes = attr.info.info_len;
    return result;
}

static int verify_info(const struct probe *probe, const struct inspection *result)
{
    const size_t required = offsetof(struct bpf_prog_info, xlated_prog_len)
                            + sizeof(result->info.xlated_prog_len);
    if (result->error)
        return report_error(probe, "GET_INFO", result->error);
    if (result->returned_bytes < required || result->info.type != (__u32)probe->type) {
        fprintf(stderr, "%s: incomplete or mismatched program info\n", probe->name);
        return report_error(probe, "INFO_ABI", EPROTO);
    }
    printf("probe=%s type=%u expected_attach_type=%u jited_prog_len=%u "
           "xlated_prog_len=%u\n", probe->name, (__u32)probe->type,
           (__u32)probe->attach_type, result->info.jited_prog_len,
           result->info.xlated_prog_len);
    if (!result->info.jited_prog_len) {
        fprintf(stderr, "%s: load succeeded but JIT was not confirmed; "
                "zero length can also reflect insufficient inspection privileges\n", probe->name);
        return report_error(probe, "JIT_NOT_CONFIRMED", ENODATA);
    }
    return 0;
}

static int run_probe(const struct probe *probe)
{
    char *log = calloc(PROBE_LOG_BYTES, 1);
    if (!log)
        return report_error(probe, "ALLOC_LOG", ENOMEM);
    const int btf_fd = probe->needs_btf ? load_probe_btf(log) : -1;
    if (probe->needs_btf && btf_fd < 0) {
        report_error(probe, "BTF_LOAD", errno);
        fprintf(stderr, "%s: BTF log (may be truncated):\n%.*s\n",
                probe->name, PROBE_LOG_BYTES, log);
        free(log);
        return 1;
    }
    memset(log, 0, PROBE_LOG_BYTES);
    const int fd = load_program(probe, log, btf_fd);
    const int load_error = errno;
    int failed = 0;
    if (btf_fd >= 0) {
        if (close(btf_fd) != 0)
            failed |= report_error(probe, "BTF_CLOSE", errno);
        else
            printf("probe=%s btf_load=success btf_fd_closed=yes\n", probe->name);
    }
    if (fd < 0) {
        report_error(probe, "LOAD", load_error);
        fprintf(stderr, "%s: verifier log (capacity=%u, may be truncated):\n%.*s\n",
                probe->name, (unsigned)PROBE_LOG_BYTES, PROBE_LOG_BYTES, log);
        free(log);
        return 1;
    }
    free(log);
    const struct inspection result = inspect_program(fd);
    const int close_result = close(fd);
    const int close_error = errno;
    failed |= verify_info(probe, &result);
    if (close_result != 0)
        failed |= report_error(probe, "CLOSE", close_error);
    if (!failed)
        printf("probe=%s status=PASS fd_closed=yes\n", probe->name);
    return failed;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        puts("Usage: bpf-probe [--help]\n"
             "Only BTF_LOAD/PROG_LOAD/GET_INFO/CLOSE; requires Linux BPF privileges.\n"
             "Exit 0: all probes loaded and JIT confirmed; 1: failure; 2: usage.\n"
             "Does not execute helpers, attach, test CO-RE or validate full dae.");
        return 0;
    }
    if (argc != 1) {
        fputs("Usage: bpf-probe [--help]\n", stderr);
        return 2;
    }
    unsigned failures = 0;
    puts("scope=program_btf_load_and_jit_only attach=no execute=no "
         "kernel_btf_tested=no core_tested=no dae_tested=no");
    for (size_t index = 0; index < ARRAY_COUNT(probes); ++index)
        failures += (unsigned)run_probe(&probes[index]);
    printf("summary=%s probes=%zu failures=%u\n",
           failures ? "FAIL" : "PASS", ARRAY_COUNT(probes), failures);
    return failures ? 1 : 0;
}
