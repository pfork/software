#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

/** wraps a commands output into base64
 */

int main(int argc, char *argv[]) {
  int pfd[2];
  pid_t ppid, bpid;

  if(argc<3) {
    fprintf(stderr,"usage: %s <string> cmd param1 param2 ... paramN\n", argv[0]);
    return -1;
  }

  pipe(pfd);
  printf("----- begin %s armor -----\n", argv[1]);

  if((ppid = fork()) == -1) {
    perror("fork");
    exit(1);
  }
  if(ppid == 0) {
    // set pfd[1]
    dup2(pfd[1], STDOUT_FILENO);
    close(pfd[0]);
    close(pfd[1]);
    // exec cmd with argv
    execvp(argv[2], &argv[2]);
    exit(0);
  }

  // pipe output into base64
  if((bpid = fork()) == -1) {
    perror("fork");
    exit(1);
  }
  if(bpid == 0) {
    // set pfd[0]
    dup2(pfd[0], STDIN_FILENO);
    close(pfd[0]);
    close(pfd[1]);
    // exec base64
    execlp("base64","base64",(char*) NULL);
    exit(0);
  }

  close(pfd[0]);
  close(pfd[1]);

  int wstatus;
  while(wait(&wstatus) > 0) {
    if(WIFEXITED(wstatus) && WEXITSTATUS(wstatus)) {
      fprintf(stderr,"exited, status=%d\n", WEXITSTATUS(wstatus));
      return 1;
    } else if (WIFSIGNALED(wstatus)) {
      fprintf(stderr,"killed by signal %d\n", WTERMSIG(wstatus));
      return 1;
    }
  }

  fflush(stdout);
  printf("----- end %s armor -----\n", argv[1]);

  return 0;
}
