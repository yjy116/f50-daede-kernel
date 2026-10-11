#define _GNU_SOURCE
/* Build: gcc -static -O2 -Wall -Wextra -Werror -std=c11 bpf72-probe.c -o bpf72-probe
 * Run only when explicitly authorized on the target. No hooks are attached and
 * no routes are changed. Success is not Honk/dae end-to-end validation.
 */
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

enum {
    MAP_ENTRY_CAPACITY = 1,
    MAP_KEY = 23,
    SOCKET_RETURN_VALUE = 7,
    CLASSIFIER_RETURN_VALUE = 0,
    PROGRAM_INSTRUCTION_COUNT = 2,
    VERIFIER_LOG_BYTES = 65536,
    TEST_PACKET_BYTES = 64,
    TEST_REPETITIONS = 1,
    EXPECTED_BTF_VERSION = 1
};

static const uint64_t MAP_VALUE = UINT64_C(0x7250b9f1);
static const char BTF_PATH[] = "/sys/kernel/btf/vmlinux";

static void fail_message(const char *stage)
{
    fprintf(stderr, "FAIL: %s\n", stage);
    exit(EXIT_FAILURE);
}

static void fail_errno(const char *stage)
{
    const int error = errno;
    fprintf(stderr, "FAIL: %s: %s (errno=%d)\n", stage, strerror(error), error);
    exit(EXIT_FAILURE);
}

static void close_checked(int fd)
{
    if (close(fd) != 0)
        fail_errno("close");
}

static int bpf_call(enum bpf_cmd command, union bpf_attr *attributes)
{
    return (int)syscall(SYS_bpf, command, attributes, sizeof(*attributes));
}

static int create_hash_map(void)
{
    union bpf_attr attributes = {0};
    attributes.map_type = BPF_MAP_TYPE_HASH;
    attributes.key_size = sizeof(uint32_t);
    attributes.value_size = sizeof(uint64_t);
    attributes.max_entries = MAP_ENTRY_CAPACITY;
    memcpy(attributes.map_name, "f50_bpf_hash", sizeof("f50_bpf_hash"));
    const int fd = bpf_call(BPF_MAP_CREATE, &attributes);
    if (fd < 0)
        fail_errno("BPF_MAP_CREATE HASH");
    return fd;
}

static void verify_hash_map(void)
{
    const int fd = create_hash_map();
    const uint32_t key = MAP_KEY;
    const uint64_t value = MAP_VALUE;
    uint64_t returned = 0;
    union bpf_attr attributes = {0};
    attributes.map_fd = (__u32)fd;
    attributes.key = (__u64)(uintptr_t)&key;
    attributes.value = (__u64)(uintptr_t)&value;
    attributes.flags = BPF_ANY;
    if (bpf_call(BPF_MAP_UPDATE_ELEM, &attributes) != 0)
        fail_errno("BPF_MAP_UPDATE_ELEM");
    attributes.value = (__u64)(uintptr_t)&returned;
    if (bpf_call(BPF_MAP_LOOKUP_ELEM, &attributes) != 0)
        fail_errno("BPF_MAP_LOOKUP_ELEM");
    if (returned != value)
        fail_message("HASH map lookup returned the wrong value");
    close_checked(fd);
    puts("PASS: HASH map create/update/lookup; fd closed");
}

static int load_program(enum bpf_prog_type type, int return_value)
{
    const struct bpf_insn instructions[PROGRAM_INSTRUCTION_COUNT] = {
        {.code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0,
         .imm = return_value},
        {.code = BPF_JMP | BPF_EXIT}
    };
    const char license[] = "GPL";
    char verifier_log[VERIFIER_LOG_BYTES] = {0};
    union bpf_attr attributes = {0};
    attributes.prog_type = type;
    attributes.insn_cnt = PROGRAM_INSTRUCTION_COUNT;
    attributes.insns = (__u64)(uintptr_t)instructions;
    attributes.license = (__u64)(uintptr_t)license;
    attributes.log_buf = (__u64)(uintptr_t)verifier_log;
    attributes.log_size = sizeof(verifier_log);
    attributes.log_level = 1;
    const int fd = bpf_call(BPF_PROG_LOAD, &attributes);
    if (fd < 0) {
        const int error = errno;
        fprintf(stderr, "FAIL: BPF_PROG_LOAD type=%u: %s (errno=%d)\n"
                "Verifier log:\n%.*s\n", (unsigned)type, strerror(error),
                error, VERIFIER_LOG_BYTES, verifier_log);
        exit(EXIT_FAILURE);
    }
    return fd;
}

static void verify_jit(int fd, enum bpf_prog_type type)
{
    struct bpf_prog_info info = {0};
    union bpf_attr attributes = {0};
    attributes.info.bpf_fd = (__u32)fd;
    attributes.info.info_len = sizeof(info);
    attributes.info.info = (__u64)(uintptr_t)&info;
    if (bpf_call(BPF_OBJ_GET_INFO_BY_FD, &attributes) != 0)
        fail_errno("BPF_OBJ_GET_INFO_BY_FD");
    const size_t required = offsetof(struct bpf_prog_info, jited_prog_len)
                            + sizeof(info.jited_prog_len);
    if (attributes.info.info_len < required || info.type != (__u32)type)
        fail_message("program info is incomplete or has a different type");
    if (info.jited_prog_len == 0)
        fail_message("JIT not confirmed: jited_prog_len is zero");
    printf("PASS: program type=%u loaded; jited_prog_len=%u\n",
           (unsigned)type, info.jited_prog_len);
}

static void verify_socket_execution(int fd)
{
    const unsigned char packet[TEST_PACKET_BYTES] = {0};
    unsigned char output[TEST_PACKET_BYTES] = {0};
    union bpf_attr attributes = {0};
    attributes.test.prog_fd = (__u32)fd;
    attributes.test.data_in = (__u64)(uintptr_t)packet;
    attributes.test.data_out = (__u64)(uintptr_t)output;
    attributes.test.data_size_in = sizeof(packet);
    attributes.test.data_size_out = sizeof(output);
    attributes.test.repeat = TEST_REPETITIONS;
    if (bpf_call(BPF_PROG_TEST_RUN, &attributes) != 0)
        fail_errno("BPF_PROG_TEST_RUN SOCKET_FILTER");
    if (attributes.test.retval != SOCKET_RETURN_VALUE)
        fail_message("SOCKET_FILTER test run returned the wrong value");
    printf("PASS: SOCKET_FILTER test run retval=%u\n", attributes.test.retval);
}

static void verify_programs(void)
{
    const int socket_fd = load_program(BPF_PROG_TYPE_SOCKET_FILTER,
                                       SOCKET_RETURN_VALUE);
    verify_jit(socket_fd, BPF_PROG_TYPE_SOCKET_FILTER);
    verify_socket_execution(socket_fd);
    close_checked(socket_fd);
    const int classifier_fd = load_program(BPF_PROG_TYPE_SCHED_CLS,
                                           CLASSIFIER_RETURN_VALUE);
    verify_jit(classifier_fd, BPF_PROG_TYPE_SCHED_CLS);
    close_checked(classifier_fd);
    puts("PASS: program fds closed; no network hooks attached");
}

static void verify_btf_header(const struct btf_header *header, uint64_t file_size)
{
    if (header->magic != BTF_MAGIC || header->version != EXPECTED_BTF_VERSION)
        fail_message("kernel BTF magic or version is invalid");
    if (header->hdr_len < sizeof(*header) || header->hdr_len > file_size)
        fail_message("kernel BTF header size is invalid");
    const uint64_t payload_size = file_size - header->hdr_len;
    const uint64_t type_end = (uint64_t)header->type_off + header->type_len;
    const uint64_t string_end = (uint64_t)header->str_off + header->str_len;
    if (header->type_len == 0 || header->str_len == 0)
        fail_message("kernel BTF type or string section is empty");
    if (type_end > payload_size || string_end > payload_size)
        fail_message("kernel BTF section extends beyond file size");
}

static void verify_kernel_btf(void)
{
    const int fd = open(BTF_PATH, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        fail_errno("open /sys/kernel/btf/vmlinux read-only");
    struct stat metadata = {0};
    if (fstat(fd, &metadata) != 0)
        fail_errno("fstat kernel BTF");
    if (metadata.st_size < (off_t)sizeof(struct btf_header))
        fail_message("kernel BTF file is shorter than its header");
    struct btf_header header = {0};
    const ssize_t bytes = pread(fd, &header, sizeof(header), 0);
    if (bytes < 0)
        fail_errno("read kernel BTF header");
    if (bytes != (ssize_t)sizeof(header))
        fail_message("short read of kernel BTF header");
    verify_btf_header(&header, (uint64_t)metadata.st_size);
    close_checked(fd);
    printf("PASS: kernel BTF magic=0x%04x header=%u size=%" PRIu64 "\n",
           (unsigned)header.magic, header.hdr_len, (uint64_t)metadata.st_size);
}

int main(void)
{
    verify_hash_map();
    verify_programs();
    verify_kernel_btf();
    puts("PASS: minimal BPF/JIT/BTF probe; Honk/dae end-to-end was not tested");
    return EXIT_SUCCESS;
}
