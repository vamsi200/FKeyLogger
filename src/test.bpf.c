#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

//ssize_t vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
SEC("kprobe/vfs_read")
int handle_vfs_read(struct pt_regs *ctx)
{
	//PT_REGS_PARM1 will get the first argument passed to vfs_read() that is a file struct, essentially meaning, get the file that is being read.
	struct file *file = (struct file *)PT_REGS_PARM1(ctx);
	struct inode *inode;
	dev_t dev;

	if (!file)
		return 0;

	inode = BPF_CORE_READ(file, f_inode);
	// this will get the device id, which contains the major and minor numbers
	dev = BPF_CORE_READ(inode, i_rdev);

	unsigned int major = dev >> 20;
	unsigned int minor = dev & 0xFFF;
	// major 13 is /dev/input and minor 64-95 are event1, event2..
	if (major == 13 && minor >= 64 && minor <= 95) {
		int pid = bpf_get_current_pid_tgid() >> 32;
		bpf_printk("PID %d read from /dev/input/event* device\n and event - %d", pid,
			   minor);
	}

	return 0;
}
