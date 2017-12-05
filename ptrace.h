#ifndef PTRACE_H
#define PTRACE_H

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>


int ptrace_traceme(void){
	int rc;
	if(rc = ptrace(PT_TRACE_ME, 0, NULL, 0) < 0){
		perror("ptrace(PT_TRACE_ME)");
		exit(1);
	}
	return rc;
}

int ptrace_get_regs(int pid, struct reg *reg){
	int rc;
	if(rc = ptrace(PT_GETREGS, pid, (caddr_t)reg, 0) < 0){
		perror("ptrace(PT_GETREGS)");
		exit(1);
	}
	return rc;
}

int ptrace_set_regs(int pid, struct reg *reg){
	int rc;
	if(rc = ptrace(PT_SETREGS, pid, (caddr_t)reg, 0) < 0){
		perror("ptrace(PT_SETREGS)");
		exit(1);
	}
	return rc;
}

int ptrace_attach(int pid){
	int rc;
	if(rc = ptrace(PT_ATTACH, pid, (caddr_t)1, 0) < 0){
		perror("ptrace(PT_ATTACH)");
		exit(1);
	}
	return rc;
}

int ptrace_cont(int pid){
	int rc;
	if(rc = ptrace(PT_CONTINUE, pid, (caddr_t)1, 0) < 0){
		perror("ptrace(PT_CONTINUE)");
		exit(1);
	}
	return rc;
}

int ptrace_detach(int pid){
	int rc;
	if(rc = ptrace(PT_DETACH, pid, (caddr_t)1, 0) < 0){
		perror("ptrace(PT_DETACH)");
		exit(1);
	}
	return rc;
}

int ptrace_write_i(int pid, unsigned long int addr, long buf){
	int rc;
	if(rc = ptrace(PT_WRITE_I, pid, (caddr_t)addr, buf) < 0){
		perror("ptrace(PT_WRITE_I)");
		exit(1);
	}
	return rc;
}

int ptrace_write_d(int pid, unsigned long int addr, long buf){
	int rc;
	if(rc = ptrace(PT_WRITE_D, pid, (caddr_t)addr, buf) < 0){
		perror("ptrace(PT_WRITE_D)");
		exit(1);
	}
	return rc;
}

int ptrace_read_i(int pid, unsigned long int addr){
	return ptrace(PT_READ_I, pid, (caddr_t)addr, 0);
}

int ptrace_read_d(int pid, unsigned long int addr){
	return ptrace(PT_READ_D, pid, (caddr_t)addr, 0);
}

int ptrace_step(int pid){
	int rc;
	if(rc = ptrace(PT_STEP, pid, (caddr_t)1, 0) < 0){
		perror("ptrace(PT_STEP)");
		exit(1);
	}
	return rc;
}

int ptrace_get_fsbase(int pid, unsigned long *fs_base){
	int rc;
	if(rc = ptrace(PT_GETFSBASE, pid, (caddr_t)fs_base, 0) < 0){
		perror("ptrace(PT_GETFSBASE)");
		exit(1);
	}
	return rc;
}

int ptrace_get_gsbase(int pid, unsigned long *gs_base){
	int rc;
	if(rc = ptrace(PT_GETGSBASE, pid, (caddr_t)gs_base, 0) < 0){
		perror("ptrace(PT_GETGSBASE)");
		exit(1);
	}
	return rc;
}

void waitpro(int pid, int *status){
	if(waitpid(pid, status, 0) < 0){
		perror("waitpid");
		exit(1);
	}
}

#endif
