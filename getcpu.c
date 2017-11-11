#define _WITH_DPRINTF
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <string.h>
#include <stdlib.h>

int getregs(pid_t pid);
/*
 * get register status
 * must run  ptrace(PT_ATTACH) before call this function
 * "pid" is target Process Identify, "fd" is file descriptor of dump file
 */

int getregs(pid_t pid){
	struct reg reg;
	int rc;
	int fd;
	unsigned long fs_base, gs_base;

	fd = open_dump_file(pid, "regs");

	memset(&reg, 0, sizeof(reg));

		
	rc = ptrace(PT_GETREGS, pid, (caddr_t)&reg, 0);
	if(rc < 0){
		perror("ptrace(PT_GETREGS)");
		exit (1);
	}

	rc = ptrace(PT_GETFSBASE, pid, (caddr_t)&fs_base, 0);
	if(rc < 0){
		perror("ptrace(PT_GETFSBASE)");
		exit (1);
	}

	rc = ptrace(PT_GETGSBASE, pid, (caddr_t)&gs_base, 0);
	if(rc < 0){
		perror("ptrace(PT_GETGSBASE)");
		exit (1);
	}
	printf("RAX: %lx excuted\n", reg.r_rax);
	printf("RBX: %lx excuted\n", reg.r_rbx);
	printf("RCX: %lx excuted\n", reg.r_rcx);
	printf("RDX: %lx excuted\n", reg.r_rdx);
	printf("RSI: %lx excuted\n", reg.r_rsi);
	printf("RDI: %lx excuted\n", reg.r_rdi);
	printf("RBP: %lx excuted\n", reg.r_rbp);
	printf("RSP: %lx excuted\n", reg.r_rsp);
	printf("RIP: %lx excuted\n", reg.r_rip);
	printf("FLG: %lx excuted\n", reg.r_rflags);
	printf("R8 : %lx excuted\n", reg.r_r8);
	printf("R9 : %lx excuted\n", reg.r_r9);
	printf("R10: %lx excuted\n", reg.r_r10);
	printf("R11: %lx excuted\n", reg.r_r11);
	printf("R12: %lx excuted\n", reg.r_r12);
	printf("R13: %lx excuted\n", reg.r_r13);
	printf("R14: %lx excuted\n", reg.r_r14);
	printf("R15: %lx excuted\n", reg.r_r15);
	printf("TRA: %lx excuted\n", reg.r_trapno);
	printf("CS : %lx excuted\n", reg.r_cs);
	printf("SS : %lx excuted\n", reg.r_ss);
	printf("DS : %x excuted\n", reg.r_ds);
	printf("ES : %x excuted\n", reg.r_es);
	printf("FS : %x excuted\n", reg.r_fs);
	printf("GS : %x excuted\n", reg.r_gs);
	printf("FSB: %x excuted\n", fs_base);
	printf("GSB: %x excuted\n", gs_base);

	write(fd, &reg, sizeof(reg));
	
	return rc;

}
