#ifndef __CR_CRTOOLS_H__
#define __CR_CRTOOLS_H__

#include <sys/types.h>
#include "servicefd.h"

#define CR_FD_PERM	(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

extern int cr_dump_tasks(pid_t pid);
extern int cr_restore_tasks(pid_t pid, char* str);

#endif
