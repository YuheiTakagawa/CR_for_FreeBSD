#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "ptrace.h"

int ptrace_traceme(void){
	int rc;
	rc = ptrace(PT_TRACE_ME, 0, NULL, 0);
	if(rc < 0){
		perror("ptrace(PT_TRACE_ME)");
		exit(1);
	}
	return rc;
}

int ptrace_get_regs(pid_t pid, struct reg *reg){
	int rc;
	rc = ptrace(PT_GETREGS, pid, (caddr_t)reg, 0);
	if(rc < 0){
		perror("ptrace(PT_GETREGS)");
		exit(1);
	}
	return rc;
}

int ptrace_set_regs(pid_t pid, struct reg *reg){
	int rc;
	rc = ptrace(PT_SETREGS, pid, (caddr_t)reg, 0);
	if(rc < 0){
		perror("ptrace(PT_SETREGS)");
		exit(1);
	}
	return rc;
}

int ptrace_attach(pid_t pid){
	int rc;
	rc = ptrace(PT_ATTACH, pid, (caddr_t)1, 0);
	if(rc < 0){
		perror("ptrace(PT_ATTACH)");
		exit(1);
	}
	return rc;
}

int ptrace_cont(pid_t pid){
	int rc;
	rc = ptrace(PT_CONTINUE, pid, (caddr_t)1, 0);
	if(rc < 0){
		perror("ptrace(PT_CONTINUE)");
		exit(1);
	}
	return rc;
}

int ptrace_detach(pid_t pid){
	int rc;
	rc = ptrace(PT_DETACH, pid, (caddr_t)1, 0);
	if(rc < 0){
		perror("ptrace(PT_DETACH)");
		exit(1);
	}
	return rc;
}

int ptrace_write_i(pid_t pid, unsigned long int addr, long buf){
	int rc;
	rc = ptrace(PT_WRITE_I, pid, (caddr_t)addr, buf);
	if(rc < 0){
		perror("ptrace(PT_WRITE_I)");
		exit(1);
	}
	return rc;
}

int ptrace_write_d(pid_t pid, unsigned long int addr, long buf){
	int rc;
	rc = ptrace(PT_WRITE_D, pid, (caddr_t)addr, buf);
	if(rc < 0){
		perror("ptrace(PT_WRITE_D)");
		exit(1);
	}
	return rc;
}

int ptrace_read_i(pid_t pid, unsigned long int addr){
	return ptrace(PT_READ_I, pid, (caddr_t)addr, 0);
}

int ptrace_read_d(pid_t pid, unsigned long int addr){
	return ptrace(PT_READ_D, pid, (caddr_t)addr, 0);
}

int ptrace_peek_area(pid_t pid, void *dst, void *addr, long bytes){
	unsigned long w;
	if(bytes & (sizeof(long) - 1))
		return -1;
	for(w = 0; w < bytes / sizeof(long); w++){
		unsigned long *d = dst, *a = addr;
		d[w] = ptrace(PT_READ_D, pid, (caddr_t)a + w, 0);
	       	if(d[w] == -1U && errno){
			perror("ptrace PT_READ_D");
	       		goto err;
		}
	}
	return 0;
err:
	return -2;
}	

int ptrace_poke_area(pid_t pid, void *src, void *addr, long bytes){
	unsigned long w;
	if(bytes & (sizeof(long) - 1))
		return -1;
	for(w = 0; w < bytes /sizeof(long); w++){
		unsigned long *s = src, *a = addr;
		if(ptrace(PT_WRITE_D, pid, (caddr_t)a + w, s[w])){
			perror("ptrace PT_WRITE_D");
			goto err;
		}
	}
	return 0;
err:
	return -2;
}

int ptrace_swap_area(pid_t pid, void *dst, void *src, long bytes){
	void *t = alloca(bytes);

	if(ptrace_peek_area(pid, t, dst, bytes))
		return -1;

	if(ptrace_poke_area(pid, src, dst, bytes)){
		if(ptrace_poke_area(pid, t, dst, bytes))
			return -2;
		return -1;
	}

	memcpy(src, t, bytes);

	return 0;
}

int ptrace_step(pid_t pid){
	int rc;
	rc = ptrace(PT_STEP, pid, (caddr_t)1, 0);
	if(rc < 0){
		perror("ptrace(PT_STEP)");
		exit(1);
	}
	return rc;
}

int ptrace_set_fsbase(pid_t pid, unsigned long *fs_base){
	int rc;
	rc = ptrace(PT_SETFSBASE, pid, (caddr_t)fs_base, 0);
	if(rc < 0){
		perror("ptrace(PT_SETFSBASE)");
		exit(1);
	}
	return rc;
}

int ptrace_get_fsbase(pid_t pid, unsigned long *fs_base){
	int rc;
	rc = ptrace(PT_GETFSBASE, pid, (caddr_t)fs_base, 0);
	if(rc < 0){
		perror("ptrace(PT_GETFSBASE)");
		exit(1);
	}
	return rc;
}

int ptrace_get_gsbase(pid_t pid, unsigned long *gs_base){
	int rc;
	rc = ptrace(PT_GETGSBASE, pid, (caddr_t)gs_base, 0);
	if(rc < 0){
		perror("ptrace(PT_GETGSBASE)");
		exit(1);
	}
	return rc;
}

void waitpro(pid_t pid, int *status){
	if(waitpid(pid, status, 0) < 0){
		perror("waitpid");
		exit(1);
	}
}

