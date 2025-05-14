#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
char LICENSE[] SEC("license") = "GPL";

#define MAJOR(dev) ((unsigned int)((dev) >> 20))
#define MINOR(dev) ((unsigned int)((dev) & 0xfffff))

struct event_t {
  u32 pid;
  u32 major;
  u32 minor;
  char type[10];
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u8));
  __uint(max_entries, 10240);
} seen_pids SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
  __uint(max_entries, 1024);
} events SEC(".maps");

SEC("kprobe/vfs_read")
int handle_vfs_read(struct pt_regs *ctx) {
  struct file *file = (struct file *)PT_REGS_PARM1(ctx);
  if (!file)
    return 0;

  struct inode *inode = BPF_CORE_READ(file, f_inode);
  dev_t dev = BPF_CORE_READ(inode, i_rdev);

  unsigned int major = MAJOR(dev);
  unsigned int minor = MINOR(dev);

  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u8 dummy = 1;

  if (bpf_map_lookup_elem(&seen_pids, &pid))
    return 0;

  if ((major == 13 && minor >= 64 && minor <= 95) || (major < 240)) {
    bpf_map_update_elem(&seen_pids, &pid, &dummy, BPF_ANY);

    struct event_t ev = {
        .pid = pid,
        .major = major,
        .minor = minor,
    };

    if (major == 13) {
      __builtin_memcpy(ev.type, "input", 10);
    }
    if (major == 240) {
      __builtin_memcpy(ev.type, "hidraw", 10);
    }
    if (major == 180) {
      __builtin_memcpy(ev.type, "hiddev", 10);
    }

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
  }

  return 0;
}
