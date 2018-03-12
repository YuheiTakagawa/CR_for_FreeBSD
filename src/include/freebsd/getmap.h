#ifndef __GET_VM_
#define __GET_VM_

#include <stdio.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <libprocstat.h>

#include "files.h"

#define SHOW_VMMAP 0
#define DUMP_VMMAP 1

struct vmds{
	unsigned long int hsize;
	unsigned long int ssize;
	unsigned long int haddr;
	unsigned long int saddr;
};

void get_vmmap(int pid, struct vmds *vmds, int flag);

void show_vmmap(pid_t pid, struct vmds *vmds);

void dump_vmmap(pid_t pid, struct vmds *vmds);

#endif
