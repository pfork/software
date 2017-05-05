#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "forkutils.h"

/** wraps a commands so that standard input is base64 decoded
 */

int main(int argc, char *argv[]) {
  int pfd[2], bfd[2];
  pid_t ppid, bpid;

  if(argc<3) {
    fprintf(stderr,"usage: %s <string> cmd param1 param2 ... paramN\n", argv[0]);
    return 1;
  }

  if(pipe(pfd) == -1) {
    perror("pipe");
    exit(1);
  }

  // fork wrapped process
  if((ppid = fork()) == -1) {
    perror("fork");
    exit(1);
  }
  if(ppid == 0) {
    // set pfd[1]
    if(dup2(pfd[0], STDIN_FILENO)==-1) {
      perror("dup2 cmd");
      exit(1);
    }
    close(pfd[0]);
    close(pfd[1]);
    // exec cmd with argv
    execvp(argv[2], &argv[2]);
    perror("running cmd");
    exit(1);
  }

  close(pfd[0]);

  // need a second pipe to remove start/end markers
  if(pipe(bfd) == -1) {
    perror("unwrap pipe");
    exit(1);
  }
  // pipe input into base64
  if((bpid = fork()) == -1) {
    perror("fork");
    exit(1);
  }
  if(bpid == 0) {
    // set pfd[0]
    if(dup2(pfd[1], STDOUT_FILENO) == -1) {
      perror("dup2 stdout base64");
      exit(1);
    }
    if(dup2(bfd[0], STDIN_FILENO) == -1) {
      perror("dup2 stdin base64");
      exit(1);
    }
    close(pfd[1]);
    close(bfd[0]);
    close(bfd[1]);
    // exec base64
    execlp("base64","base64", "-d", (char*) NULL);
    perror("running base64");
    exit(1);
  }

  close(pfd[1]);
  close(bfd[0]);

  // need to remove the start/end markers around the base64 blob
  char *line;
  size_t len, a;
  // find start of armor
  while(1) {
    line=NULL;
    if((len=getline(&line, &a, stdin)) == (size_t)-1) {
      fprintf(stderr, "err: couldn't find start of armor\n");
      perror("find start");
      exit(1);
    }
    if(len==25+strlen(argv[1]) &&
       memcmp(line,"----- begin ",12)==0 &&
       memcmp(line+12,argv[1],strlen(argv[1]))==0 &&
       memcmp(line+12+strlen(argv[1]), " armor -----\n", 14)==0) break;
    free(line);
  };

  free(line);
  // dump until end of armor
  while(1) {
    line=NULL;
    if((len=getline(&line, &a, stdin)) == (size_t)-1) {
      perror("unwrap");
      exit(1);
    }
    if(len==23+strlen(argv[1]) &&
       memcmp(line,"----- end ",10)==0 &&
       memcmp(line+10,argv[1],strlen(argv[1]))==0 &&
       memcmp(line+10+strlen(argv[1]), " armor -----\n", 14)==0) break;
    if(write(bfd[1], line, len) != (ssize_t) len) {
      perror("write blob");
      exit(1);
    }
    free(line);
  };
  free(line);
  close(bfd[1]);

  finish(bpid, ppid, argv[2]);

  return 0;
}
