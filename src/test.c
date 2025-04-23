#include <fcntl.h>
#include <linux/input.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
  const char *device = "/dev/input/event5";
  int fd = open(device, O_RDONLY);
  if (fd == -1) {
    perror("Failed to open device");
    return EXIT_FAILURE;
  }

  struct input_event ev;
  while (read(fd, &ev, sizeof(ev)) > 0) {
    if (ev.type == EV_KEY && ev.value == 1) {
      printf("Key pressed: %d\n", ev.code);
    }
  }

  close(fd);
  return EXIT_SUCCESS;
}
