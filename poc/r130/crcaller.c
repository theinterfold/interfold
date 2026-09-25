#define _GNU_SOURCE
#include <sys/resource.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
int main(int argc, char **argv){
  (void)argc; (void)argv;
  struct rlimit rl;
  rl.rlim_cur = RLIM_INFINITY;
  rl.rlim_max = RLIM_INFINITY;
  setrlimit(RLIMIT_NOFILE, &rl);
  int fd = open("/home/dev/interfold-research/interfold/target/release/.cargo-lock", O_RDWR|O_CREAT);
  if (fd >= 0) {
    if (flock(fd, LOCK_EX) == 0) { puts("fd9-hold"); }
    else { perror("flock"); }
  } else { perror("open"); }
}