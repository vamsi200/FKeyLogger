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

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u8));
  __uint(max_entries, 1024);
} seen_pids SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int handle_memfd_create(struct trace_event_raw_sys_enter *ctx) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u8 dummy = 1;

  if (bpf_map_lookup_elem(&seen_pids, &pid))
    return 0;

  bpf_map_update_elem(&seen_pids, &pid, &dummy, BPF_ANY);

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &pid, sizeof(pid));

  return 0;
}
