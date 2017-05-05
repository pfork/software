#ifndef forkutils_h
#define forkutils_h

#include <sys/wait.h>

void finish(const pid_t bpid, const pid_t ppid, const char* proc);

#endif // forkutils_h
