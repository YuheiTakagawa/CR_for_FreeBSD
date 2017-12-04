#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>

#ifndef PTRACE_H
#define PTRACE_H
int ptrace_traceme(void){
	return ptrace(PT_TRACE_ME, 0, NULL, 0);
}

int ptrace_get_regs(int pid, struct reg *reg){
	return ptrace(PT_GETREGS, pid, (caddr_t)reg, 0);
}

int ptrace_set_regs(int pid, struct reg *reg){
	return ptrace(PT_SETREGS, pid, (caddr_t)reg, 0);
}

int ptrace_attach(int pid){
	return ptrace(PT_ATTACH, pid, (caddr_t)1, 0);
}

int ptrace_cont(int pid){
	return ptrace(PT_CONTINUE, pid, (caddr_t)1, 0);
}

int ptrace_detach(int pid){
	return ptrace(PT_DETACH, pid, (caddr_t)1, 0);
}

int ptrace_write_i(int pid, unsigned long int addr, long buf){
	return ptrace(PT_WRITE_I, pid, (caddr_t)addr, buf);
}

int ptrace_write_d(int pid, unsigned long int addr, long buf){
	return ptrace(PT_WRITE_D, pid, (caddr_t)addr, buf);
}

int ptrace_read_i(int pid, unsigned long int addr){
	return ptrace(PT_READ_I, pid, (caddr_t)addr, 0);
}

int ptrace_read_d(int pid, unsigned long int addr){
	return ptrace(PT_READ_D, pid, (caddr_t)addr, 0);
}

int ptrace_step(int pid){
	return ptrace(PT_STEP, pid, (caddr_t)1, 0);
}

void waitpro(int pid, int *status){
	if(waitpid(pid, status, 0) < 0){
		perror("waitpid");
		exit(1);
	}
}

#endif
