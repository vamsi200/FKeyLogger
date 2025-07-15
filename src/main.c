#include "vfsread.skel.h"
#include <bpf/libbpf.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct event_t {
  uint32_t pid;
  uint32_t minor;
  uint32_t major;
};

static FILE *fptr = NULL;
static volatile int running = 1;

static void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz) {
  struct event_t *ev = (struct event_t *)data;

  if (!fptr)
    return;

  fprintf(fptr, "{\"pid\": %u, \"major\": %u, \"minor\": %u}\n", ev->pid,
          ev->major, ev->minor);
}

static void handle_signal(int sig) { running = 0; }

int main() {
  struct vfsread_bpf *skel = vfsread_bpf__open_and_load();
  if (!skel) {
    fprintf(stderr, "Failed to open and load BPF program\n");
    return 1;
  }

  if (vfsread_bpf__attach(skel)) {
    fprintf(stderr, "Failed to attach BPF program\n");
    vfsread_bpf__destroy(skel);
    return 1;
  }

  fptr = fopen("bpf_output.json", "a");
  if (!fptr) {
    perror("fopen");
    vfsread_bpf__destroy(skel);
    return 1;
  }

  setvbuf(fptr, NULL, _IOLBF, 0);

  struct perf_buffer_opts opts = {0};
  opts.sz = sizeof(struct perf_buffer_opts);

  struct perf_buffer *pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 8,
                                            handle_event, NULL, NULL, &opts);
  if (!pb) {
    fprintf(stderr, "Failed to create perf buffer\n");
    fclose(fptr);
    vfsread_bpf__destroy(skel);
    return 1;
  }

  signal(SIGINT, handle_signal);
  signal(SIGTERM, handle_signal);

  printf("> Program running. Press Ctrl+C to stop.\n");

  while (running) {
    int err = perf_buffer__poll(pb, 1000);
    if (err < 0 && running) {
      fprintf(stderr, "Error while polling: %d\n", err);
      break;
    }
  }

  perf_buffer__free(pb);
  vfsread_bpf__destroy(skel);

  if (fptr) {
    fclose(fptr);
  }

  printf("Exiting...\n");
  return 0;
}
