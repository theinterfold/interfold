#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <sys/types.h>
__attribute__((constructor)) static void start(void){
  time_t last = 0;
  for(;;){
    time_t t = 0;
    time(&t);
    if(t - last >= 15){
      last = t;
      FILE *f = fopen("/tmp/r130_pnpm_alive.log","a");
      if(f){ fprintf(f,"ALIVE pid=%ld\n",(long)getpid()); fclose(f); }
    }
    sleep(5);
  }
}