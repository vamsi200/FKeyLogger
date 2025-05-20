#include <stdio.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "fe.skel.h"
#include <string.h>

static volatile bool exiting = false;
static FILE *fptr = NULL;

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	__u32 pid = *(__u32 *)data;
	if (!fptr)
		return;
	fprintf(fptr, "{\"pid\": %d}\n", pid);
	fflush(fptr);
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "Lost %llu events on CPU %d\n", lost_cnt, cpu);
}

static void handle_signal(int sig)
{
	exiting = true;
}

int main()
{
	struct fe_bpf *skel;
	struct perf_buffer *pb = NULL;
	int err;

	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);

	skel = fe_bpf__open();
	fptr = fopen("memfd_create_output.json", "a");
	if (!fptr) {
		perror("fopen");
		fe_bpf__destroy(skel);
		return 1;
	}

	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	err = fe_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
		return 1;
	}

	err = fe_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
		return 1;
	}

	pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 8, handle_event, handle_lost_events,
			      NULL, NULL);
	if (!pb) {
		fprintf(stderr, "Failed to create perf buffer\n");
		return 1;
	}

	printf("> Listening for memfd_create events. Press Ctrl+C to exit.\n");

	while (!exiting) {
		err = perf_buffer__poll(pb, 100);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "Error polling perf buffer: %d\n", err);
			break;
		}
	}
	if (fptr) {
		fclose(fptr);
	}
	perf_buffer__free(pb);
	fe_bpf__destroy(skel);
	return 0;
}
