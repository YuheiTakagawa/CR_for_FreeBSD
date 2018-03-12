#ifndef __REGISTER_H__
#define __REGISTER_H__

extern int check_rip_syscall(pid_t pid, unsigned long int rip);
extern void print_regs(pid_t pid);
extern int setregs(pid_t pid, pid_t filePid);
extern int getregs(pid_t pid);

#endif
