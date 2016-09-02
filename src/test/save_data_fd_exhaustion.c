/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int main(void) {
  char msg[] = "Not out of fds yet";

  do {
    int save_fd = syscall(SYS_rrcall_open_magic_save_fd);
    if (save_fd < 0)
      break;

    ssize_t written = syscall(SYS_write, save_fd, msg, sizeof(msg));
    test_assert(written == sizeof(msg));
  } while(1);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
