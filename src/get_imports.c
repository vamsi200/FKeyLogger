#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <unistd.h>

ssize_t read_process_memory(pid_t pid, void *remote_addr, void *buffer,
                            size_t len) {
  struct iovec local[1];
  struct iovec remote[1];

  local[0].iov_base = buffer;
  local[0].iov_len = len;
  remote[0].iov_base = remote_addr;
  remote[0].iov_len = len;

  return process_vm_readv(pid, local, 1, remote, 1, 0);
}

void print_memory_as_ascii(unsigned char *buffer, ssize_t bytes_read) {
  printf("Content :\n");

  for (ssize_t i = 0; i < bytes_read; i++) {
    if (isprint(buffer[i])) {
      printf("%c", buffer[i]);
    } else {
      // printf(".");
    }
  }
  printf("\n");
}

int main(int argc, char *argv[]) {
  if (argc < 3) {
    printf("Usage: %s <PID> <Address>\n", argv[0]);
    return 1;
  }

  pid_t target_pid = atoi(argv[1]);
  void *target_address = (void *)strtoul(argv[2], NULL, 16);

  unsigned char buffer[1024];
  ssize_t bytes_read =
      read_process_memory(target_pid, target_address, buffer, sizeof(buffer));

  if (bytes_read == -1) {
    perror("process_vm_readv failed");
    return 1;
  }
  print_memory_as_ascii(buffer, bytes_read);

  return 0;
}
