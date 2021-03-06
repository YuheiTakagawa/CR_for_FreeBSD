#ifndef PARASITE_SYSCALL
#define PARASITE_SYSCALL

#include <sys/ptrace.h>
#include <sys/user.h>

#ifdef _LINUX
typedef struct user_regs_struct regs_t;
#endif
#ifdef _BSD
typedef struct reg regs_t;
#endif
struct orig{
	long text;
	long data;
	char *addr;
	regs_t reg;
};

extern void parasite_setup_regs(unsigned long new_ip, void *stack, regs_t *regs);
//static int parasite_run(pid_t pid, int cmd, unsigned long ip, void *stack, struct reg *regs, struct orig *orig);
//static int parasite_trap(pid_t pid, struct reg *regs, struct orig *orig);
extern int compel_execute_syscall(pid_t pid, struct orig *orig, regs_t *regs);

extern void compel_syscall(pid_t pid, struct orig *orig, int nr, long *ret, 
		unsigned long arg1, 
		unsigned long arg2, 
		unsigned long arg3,
		unsigned long arg4,
		unsigned long arg5,
		unsigned long arg6);
extern void *remote_mmap(pid_t pid, struct orig *orig, void *addr, size_t length, int prot, int flags, int fd, off_t offset);

extern void restore_setregs(pid_t pid, regs_t orig);
extern void restore_memory(pid_t pid, struct orig *orig);
extern void restore_orig(pid_t, struct orig *orig);

#endif
