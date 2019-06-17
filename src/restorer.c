#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <signal.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/reg.h>

#include "files.h"
#include "ptrace.h"
#include "register.h"

int restore_threads(pid_t pid, pid_t filePid){
	struct user_regs_struct reg, tmpreg;
	int fd;

	memset(&reg, 0, sizeof(reg));
	fd = open_file(filePid, "regs");
	read(fd, &reg, sizeof(reg));
	close(fd);


	/*
	 * Use register info which read from dump file
	 * but we should use only segment register allocated 
	 * by OS.
	 */

	ptrace_get_regs(pid, &tmpreg);

	reg.cs = tmpreg.cs;
	reg.ss = tmpreg.ss;
	reg.ds = tmpreg.ds;
	reg.es = tmpreg.es;
	reg.fs = tmpreg.fs;
	reg.gs = tmpreg.gs;


	check_rip_syscall(pid, reg.rip);

	inject_restorer(pid, &reg);
	

	return 0;
}
