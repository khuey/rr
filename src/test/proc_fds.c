/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

#include <dirent.h>
#include <unistd.h>

pthread_barrier_t bar;

void* thread_func(__attribute__((unused)) void* name) {
  pthread_barrier_wait(&bar);
  sleep(1);
  return NULL;
}

int main(void) {
  // Empirically tested to be enough to make ProcFdDirMonitor
  // repeat the getdents call.
  const int NUM_THREADS = 20;
  
  int i;
  for (i = 0; i < 15; i++) {
    dup(2);
  }

  /* init barrier */
  pthread_barrier_init(&bar, NULL, NUM_THREADS + 1);
  /* Create independent threads each of which will execute
   * function */
  for (i = 0; i < NUM_THREADS; i++) {
    pthread_t thread;
    pthread_create(&thread, NULL, thread_func, NULL);
  }

  pthread_barrier_wait(&bar);

  const char proc_fd_path[] = "/proc/self/fd";
  int fd = syscall(SYS_open, proc_fd_path, O_DIRECTORY);
  test_assert(fd >= 0);

  char buf[128];
  char* current;
  int bytes;
  while((bytes = syscall(SYS_getdents64, fd, &buf, sizeof(buf)))) {
    current = buf;
    while (current != buf + bytes) {
      struct dirent* ent = (struct dirent*)current;
      char* end;
      int fd = strtol(ent->d_name, &end, 10);
      if (!*end) {
        test_assert(fd < 20); // Other fds should be cloaked!
      }
      current += ent->d_reclen;
    }
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
