#ifndef PTRACE_H
#define PTRACE_H

#include <sys/ptrace.h>

extern void step_debug(pid_t pid);
extern void print_regs(pid_t pid);

extern int ptrace_traceme(void);
extern int ptrace_get_regs(pid_t pid, struct reg *reg);
extern int ptrace_set_regs(pid_t pid, struct reg *reg);
extern int ptrace_attach(pid_t pid);
extern int ptrace_cont(pid_t pid);
extern int ptrace_detach(pid_t pid);
extern int ptrace_write_i(pid_t pid, unsigned long int addr, long buf);
extern int ptrace_write_d(pid_t pid, unsigned long int addr, long buf);
extern int ptrace_read_i(pid_t pid, unsigned long int addr);
extern int ptrace_read_d(pid_t pid, unsigned long int addr);
extern int ptrace_peek_area(pid_t pid, void *dst, void *addr, long bytes);
extern int ptrace_poke_area(pid_t pid, void *src, void *addr, long bytes);
extern int ptrace_swap_area(pid_t pid, void *dst, void *src, long bytes);
extern int ptrace_step(pid_t pid);
extern int ptrace_get_fsbase(pid_t pid, unsigned long *fs_base);
extern int ptrace_get_gsbase(pid_t pid, unsigned long *gs_base);

extern void waitpro(pid_t pid, int*);

#endif
