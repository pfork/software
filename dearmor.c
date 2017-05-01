#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

/** wraps a commands so that standard input is base64 decoded
 */

int main(int argc, char *argv[]) {
  int pfd[2], bfd[2];
  pid_t ppid, bpid;

  if(argc<3) {
    fprintf(stderr,"usage: %s <string> cmd param1 param2 ... paramN\n", argv[0]);
    return -1;
  }

  pipe(pfd);
  pipe(bfd);

  // pipe input into base64
  if((bpid = fork()) == -1) {
    perror("fork");
    exit(1);
  }
  if(bpid == 0) {
    // set pfd[0]
    dup2(pfd[1], STDOUT_FILENO);
    dup2(bfd[0], STDIN_FILENO);
    close(pfd[0]);
    close(pfd[1]);
    close(bfd[0]);
    close(bfd[1]);
    // exec base64
    execlp("base64","base64", "-d", (char*) NULL);
    exit(0);
  }

  if((ppid = fork()) == -1) {
    perror("fork");
    exit(1);
  }
  if(ppid == 0) {
    // set pfd[1]
    dup2(pfd[0], STDIN_FILENO);
    close(pfd[0]);
    close(pfd[1]);
    close(bfd[0]);
    close(bfd[1]);
    // exec cmd with argv
    execvp(argv[2], &argv[2]);
    exit(0);
  }

  close(pfd[0]);
  close(pfd[1]);
  close(bfd[0]);

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
      fprintf(stderr, "err: %ld\n", len);
      perror("unwrap");
      exit(1);
    }
    if(len==23+strlen(argv[1]) &&
       memcmp(line,"----- end ",10)==0 &&
       memcmp(line+10,argv[1],strlen(argv[1]))==0 &&
       memcmp(line+10+strlen(argv[1]), " armor -----\n", 14)==0) break;
    line[len]=0;
    write(bfd[1], line, len);
    free(line);
  };
  free(line);
  close(bfd[1]);

  // wait for kids
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

  return 0;
}
