#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
int main(void){
  const char *path = "/home/dev/interfold-research/interfold/target/release/.cargo-lock";
  int fd = open(path, O_RDWR|O_CREAT, 0644);
  if (fd < 0) { perror("open"); return 1; }
  if (flock(fd, LOCK_EX) != 0) { perror("flock"); return 2; }
  puts("HOLD start"); fflush(stdout);
  for(;;) sleep(60);
  return 0;
}