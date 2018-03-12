#ifndef SETMEM
#define SETMEM

#include "common.h"
#include "parasite_syscall.h"

struct remap_vm_struct{
	unsigned long int new_addr;
	unsigned long int new_end;
	char path[BUFSIZE];
	int flags;
	int protection;
};

struct remap_vm_old{
	unsigned long int old_addr;
	unsigned long int old_size;
};

extern int setmems(pid_t pid, pid_t filePid, struct remap_vm_struct *revm);
int write_mem(int read_fd, int write_fd, long int offset);
void remap_mem(pid_t pid, struct remap_vm_struct *revm, struct remap_vm_old *revm_old, struct orig *orig);
void read_vmmap_list(pid_t filePid, struct remap_vm_struct *revm);
void remap_vm(pid_t pid, pid_t filePid, struct remap_vm_struct *revm, struct orig *orig);

#endif
