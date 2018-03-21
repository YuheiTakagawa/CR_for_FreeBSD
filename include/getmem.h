#ifndef GETMEM
#define GETMEM

#include "common.h"

extern int getmem(int read_fd, int dump_fd, long int offset, long int size);

extern int getmems(pid_t pid);

#endif
