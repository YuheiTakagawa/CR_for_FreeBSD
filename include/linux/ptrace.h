#ifndef PTRACE_H
#define PTRACE_H

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>


int ptrace_traceme(void){
	int rc;
	rc = ptrace(PT_TRACE_ME, 0, NULL, 0);
	if(rc < 0){
		perror("ptrace(PT_TRACE_ME)");
		exit(1);
	}
	return rc;
}

int ptrace_get_regs(int pid, struct user_regs_struct *reg){
	int rc;
	rc = ptrace(PT_GETREGS, pid, 0, reg);
	if(rc < 0){
		perror("ptrace(PT_GETREGS)");
		exit(1);
	}
	return rc;
}

int ptrace_set_regs(int pid, struct user_regs_struct *reg){
	int rc;
	rc = ptrace(PT_SETREGS, pid, 0, reg);
	if(rc < 0){
		perror("ptrace(PT_SETREGS)");
		exit(1);
	}
	return rc;
}

int ptrace_attach(int pid){
	int rc;
	rc = ptrace(PT_ATTACH, pid, 1, 0);
	if(rc < 0){
		perror("ptrace(PT_ATTACH)");
		exit(1);
	}
	return rc;
}

int ptrace_cont(int pid){
	int rc;
	rc = ptrace(PT_CONTINUE, pid, 1, 0);
	if(rc < 0){
		perror("ptrace(PT_CONTINUE)");
		exit(1);
	}
	return rc;
}

int ptrace_detach(int pid){
	int rc;
	rc = ptrace(PT_DETACH, pid, 1, 0);
	if(rc < 0){
		perror("ptrace(PT_DETACH)");
		exit(1);
	}
	return rc;
}

int ptrace_write_i(int pid, unsigned long int addr, long buf){
	int rc;
	rc = ptrace(PT_WRITE_I, pid, addr, buf);
	if(rc < 0){
		perror("ptrace(PT_WRITE_I)");
		exit(1);
	}
	return rc;
}

int ptrace_write_d(int pid, unsigned long int addr, long buf){
	int rc;
	rc = ptrace(PT_WRITE_D, pid, addr, buf);
	if(rc < 0){
		perror("ptrace(PT_WRITE_D)");
		exit(1);
	}
	return rc;
}

int ptrace_read_i(int pid, unsigned long int addr){
	return ptrace(PT_READ_I, pid, addr, 0);
}

int ptrace_read_d(int pid, unsigned long int addr){
	return ptrace(PT_READ_D, pid, addr, 0);
}

int ptrace_step(int pid){
	int rc;
	rc = ptrace(PT_STEP, pid, 1, 0);
	if(rc < 0){
		perror("ptrace(PT_STEP)");
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