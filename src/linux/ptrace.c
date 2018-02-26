#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>

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

int ptrace_peek_area(pid_t pid, void *dst, void *addr, long bytes){
	unsigned long w;
	if(bytes & (sizeof(long) - 1))
		return -1;
	for(w = 0; w < bytes / sizeof(long); w++){
		unsigned long *d = dst, *a = addr;
		d[w] = ptrace_read_d(pid, (unsigned long)a + w);
		if(d[w] == -1U && errno)
			goto err;
	}
	return 0;
err:
	return -2;
}

int ptrace_poke_area(pid_t pid, void *src, void *addr, long bytes){
	unsigned long w;
	if(bytes & (sizeof(long) - 1))
		return -1;
	for(w = 0; w < bytes / sizeof(long); w++){
		unsigned long *s = src, *a = addr;
		if(ptrace_write_d(pid, (unsigned long)a + w, s[w]))
				goto err;
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

int ptrace_step(int pid){
	int rc;
	rc = ptrace(PT_STEP, pid, 1, 0);
	if(rc < 0){
		perror("ptrace(PT_STEP)");
		exit(1);
	}
	return rc;
}

int ptrace_get_fsbase(pid_t pid, unsigned long *fs_base){
	struct user_regs_struct reg;
	ptrace_get_regs(pid, &reg);
	*fs_base = reg.fs_base;
	return 0;
}

int ptrace_get_gsbase(pid_t pid, unsigned long *gs_base){
	struct user_regs_struct reg;
	ptrace_get_regs(pid, &reg);
	*gs_base = reg.gs_base;
	return 0;
}

void waitpro(int pid, int *status){
	if(waitpid(pid, status, 0) < 0){
		perror("waitpid");
		exit(1);
	}
}

