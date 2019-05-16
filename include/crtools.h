#ifndef __CR_CRTOOLS_H__
#define __CR_CRTOOLS_H__

#include <sys/types.h>
#include "servicefd.h"

extern int cr_dump_tasks(pid_t pid);
extern int cr_restore_tasks(pid_t pid, char* str);

#endif
