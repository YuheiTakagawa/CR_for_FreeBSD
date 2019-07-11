#ifndef __REGISTER_H__
#define __REGISTER_H__

#include "images/core.pb-c.h"

extern int check_rip_syscall(pid_t pid, unsigned long int rip);
extern void print_regs(pid_t pid);
extern int setregs(pid_t pid, CoreEntry *ce);
extern int getregs(pid_t pid);

#endif
