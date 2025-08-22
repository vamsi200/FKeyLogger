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
  char type[12];
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

  // __AUTOGEN_DEVICE_FILTER__VFS__READ
  if ((major == 13 && minor >= 32 && minor <= 35) ||
      (major == 13 && minor >= 63 && minor <= 90) ||
      (major == 5 && minor == 0) || (major == 5 && minor == 2) ||
      (major == 136 && minor >= 0 && minor <= 2) ||
      (major == 244 && minor >= 0 && minor <= 3) ||
      (major == 10 && minor == 223)) {
    bpf_map_update_elem(&seen_pids, &pid, &dummy, BPF_ANY);
    struct event_t ev = {
        .pid = pid,
        .major = major,
        .minor = minor,
    };
    __builtin_memcpy(ev.type, "vfs_read", sizeof("vfs_read"));
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
  }
  return 0;
}

// int do_vfs_ioctl(struct file *filp, unsigned int fd, unsigned int cmd,
// unsigned long arg;

SEC("kprobe/do_vfs_ioctl")
int handle_ioctl(struct pt_regs *ctx) {
  struct file *file = (struct file *)PT_REGS_PARM1(ctx);
  if (!file)
    return 0;

  // unsigned int fd = (unsigned int)PT_REGS_PARM2(ctx);
  unsigned int cmd = (unsigned int)PT_REGS_PARM3(ctx);
  // unsigned long arg = (unsigned long)PT_REGS_PARM4(ctx);

  struct inode *inode = BPF_CORE_READ(file, f_inode);
  dev_t dev = BPF_CORE_READ(inode, i_rdev);

  unsigned int major = MAJOR(dev);
  unsigned int minor = MINOR(dev);

  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u8 dummy = 1;

  if (bpf_map_lookup_elem(&seen_pids, &pid))
    return 0;

  if (cmd == 0x40044590 /* EVIOCGRAB */ || cmd == 0x80004506 /* EVIOCGNAME */ ||
      cmd == 0x80084502 /* EVIOCGID */ ||
      (cmd & ~0xff) == 0x80044500 /* EVIOCGBIT* family */) {

    bpf_map_update_elem(&seen_pids, &pid, &dummy, BPF_ANY);

    struct event_t ev = {
        .pid = pid,
        .major = major,
        .minor = minor,
    };
    __builtin_memcpy(ev.type, "vfs_ioctl", sizeof("vfs_ioctl"));
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
  }
  return 0;
}

SEC("kprobe/vfs_write")
int handle_vfs_write(struct pt_regs *ctx) {
  struct file *file = (struct file *)PT_REGS_PARM1(ctx);
  struct inode *inode = BPF_CORE_READ(file, f_inode);
  dev_t dev = BPF_CORE_READ(inode, i_rdev);

  unsigned int major = MAJOR(dev);
  unsigned int minor = MINOR(dev);

  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u8 dummy = 1;

  if (bpf_map_lookup_elem(&seen_pids, &pid))
    return 0;

  // __AUTOGEN_DEVICE_FILTER__VFS__WRITE
  if ((major == 13 && minor >= 32 && minor <= 35) ||
      (major == 13 && minor >= 63 && minor <= 90) ||
      (major == 5 && minor == 0) || (major == 5 && minor == 2) ||
      (major == 136 && minor >= 0 && minor <= 2) ||
      (major == 244 && minor >= 0 && minor <= 3) ||
      (major == 10 && minor == 223)) {
    bpf_map_update_elem(&seen_pids, &pid, &dummy, BPF_ANY);
    struct event_t ev = {
        .pid = pid,
        .major = major,
        .minor = minor,
    };
    __builtin_memcpy(ev.type, "vfs_write", sizeof("vfs_write"));
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
  }
  return 0;
}
