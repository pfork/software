#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "forkutils.h"

/** wraps a commands output into base64
 */

int main(int argc, char *argv[]) {
  int pfd[2];
  pid_t ppid, bpid;

  if(argc<3) {
    fprintf(stderr,"usage: %s <string> cmd param1 param2 ... paramN\n", argv[0]);
    return 1;
  }

  if(pipe(pfd) == -1) {
    perror("pipe");
    exit(1);
  }

  printf("----- begin %s armor -----\n", argv[1]);

  if((ppid = fork()) == -1) {
    perror("fork");
    exit(1);
  }
  if(ppid == 0) {
    // set pfd[1]
    if(dup2(pfd[1], STDOUT_FILENO) == -1) {
      perror("process dup2 stdout");
      exit(1);
    }
    close(pfd[0]);
    close(pfd[1]);
    // exec cmd with argv
    execvp(argv[2], &argv[2]);
    perror("running cmd");
    exit(1);
  }

  // pipe output into base64
  if((bpid = fork()) == -1) {
    perror("fork");
    exit(1);
  }
  if(bpid == 0) {
    // set pfd[0]
    if(dup2(pfd[0], STDIN_FILENO) == -1) {
      perror("base64 dup");
      exit(1);
    }
    close(pfd[0]);
    close(pfd[1]);
    // exec base64
    execlp("base64","base64",(char*) NULL);
    perror("running base64");
    exit(1);
  }

  close(pfd[0]);
  close(pfd[1]);

  finish(bpid, ppid, argv[2]);

  printf("----- end %s armor -----\n", argv[1]);

  return 0;
}
