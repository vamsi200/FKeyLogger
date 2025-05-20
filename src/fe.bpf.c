#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 128);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int handle_memfd_create(struct trace_event_raw_sys_enter* ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &pid, sizeof(pid));
    return 0;
}
