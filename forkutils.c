#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>

static void procerr(const pid_t rpid, const pid_t bpid, const pid_t ppid, const char* proc) {
  if(rpid==ppid)
    fprintf(stderr,"%s ", proc);
  else if(rpid==bpid)
    fprintf(stderr,"base64 ");
  else
    fprintf(stderr,"unknown process ");
}

void finish(const pid_t bpid, const pid_t ppid, const char* proc) {
  int wstatus;
  pid_t rpid;
  while((rpid=wait(&wstatus)) > 0) {
    if(WIFEXITED(wstatus) && WEXITSTATUS(wstatus)) {
      procerr(rpid, bpid, ppid, proc);
      fprintf(stderr,"exited, status=%d\n", WEXITSTATUS(wstatus));
      exit(1);
    }
    if (WIFSIGNALED(wstatus)) {
      procerr(rpid, bpid, ppid, proc);
      fprintf(stderr,"killed by signal %d\n", WTERMSIG(wstatus));
      exit(1);
    }
  }
}
