#ifndef FILES_H
#define FILES_H

#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include "common.h"


extern int open_file(pid_t pid, char* flag);
extern int open_read_file(pid_t pid);
extern int open_dump_file(pid_t pid, char *dumptype);

#endif
