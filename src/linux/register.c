#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/user.h>
#include <sys/reg.h>


#include "files.h"
#include "ptrace.h"
#include "register.h"

int check_rip_syscall(pid_t pid, unsigned long int rip){
	
	printf("rip code:%x\n", ptrace_read_i(pid, rip));

	return 1;
}

void print_regs(pid_t pid){
	struct user_regs_struct reg;
	ptrace_get_regs(pid, &reg);
        printf("ORA: %llx excuted\n", reg.orig_rax);
	printf("RAX: %llx excuted\n", reg.rax);
        printf("RBX: %llx excuted\n", reg.rbx);
        printf("RCX: %llx excuted\n", reg.rcx);
        printf("RDX: %llx excuted\n", reg.rdx);
        printf("RSI: %llx excuted\n", reg.rsi);
        printf("RDI: %llx excuted\n", reg.rdi);
        printf("RBP: %llx excuted\n", reg.rbp);
        printf("RSP: %llx excuted\n", reg.rsp);
        printf("RIP: %llx excuted\n", reg.rip);
        printf("FLG: %llx excuted\n", reg.eflags);
        printf("R8 : %llx excuted\n", reg.r8);
        printf("R9 : %llx excuted\n", reg.r9);
        printf("R10: %llx excuted\n", reg.r10);
        printf("R11: %llx excuted\n", reg.r11);
        printf("R12: %llx excuted\n", reg.r12);
        printf("R13: %llx excuted\n", reg.r13);
        printf("R14: %llx excuted\n", reg.r14);
        printf("R15: %llx excuted\n", reg.r15);
        printf("CS : %llx excuted\n", reg.cs);
        printf("SS : %llx excuted\n", reg.ss);
        printf("DS : %llx excuted\n", reg.ds);
        printf("ES : %llx excuted\n", reg.es);
        printf("FS : %llx excuted\n", reg.fs);
        printf("GS : %llx excuted\n", reg.gs);

}

int setregs(pid_t pid, pid_t filePid){
	struct user_regs_struct reg, tmpreg;
	int fd;

	memset(&reg, 0, sizeof(reg));
	fd = open_file(filePid, "regs");
	read(fd, &reg, sizeof(reg));


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

	if(ptrace_set_regs(pid, &reg) < 0){
	perror("ptrace(PT_SETREGS, ...)");
	exit(1);
	}
	return 0;
}

/*
 * get register status
 * must run ptrace(PT_ATTACH) before call this function
 * "pid" is target Process Identify, "fd" is file descriptor of dump file
 */

int getregs(pid_t pid){
	struct user_regs_struct reg;
	int fd;

	fd = open_dump_file(pid, "regs");

	memset(&reg, 0, sizeof(reg));

	ptrace_get_regs(pid, &reg);

	write(fd, &reg, sizeof(reg));

	return 0;
}

