#include "test.skel.h"
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <bpf/libbpf.h>

struct event_t {
	uint32_t pid;
	uint32_t minor;
	uint32_t major;
};
FILE *fptr;
static void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
	struct event_t *ev = (struct event_t *)data;
	fptr = fopen("bpf_output.txt", "a");
	if (!fptr) {
		perror("fopen");
		return;
	}
	fprintf(fptr, "%d %d %d\n", ev->pid, ev->minor, ev->major);
	fclose(fptr);
}

int main()
{
	struct test_bpf *skel = test_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF program\n");
		return 1;
	}

	if (test_bpf__attach(skel)) {
		fprintf(stderr, "Failed to attach BPF program\n");
		test_bpf__destroy(skel);
		return 1;
	}

	struct perf_buffer_opts opts = { 0 };
	opts.sz = sizeof(struct perf_buffer_opts);

	struct perf_buffer *pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 8, handle_event,
						  NULL, NULL, &opts);
	if (!pb) {
		fprintf(stderr, "Failed to create perf buffer\n");
		test_bpf__destroy(skel);
		return 1;
	}

	printf("Program loaded! Waiting...\n");

	while (1) {
		int err = perf_buffer__poll(pb, 1000);
		if (err < 0) {
			fprintf(stderr, "Error while polling: %d\n", err);
			break;
		}
	}

	perf_buffer__free(pb);
	test_bpf__destroy(skel);
	return 0;
}
