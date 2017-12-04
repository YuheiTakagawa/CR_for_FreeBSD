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

#include "register.c"
#include "ptrace.h"

int getregs(pid_t pid);
/*
 * get register status
 * must run  ptrace(PT_ATTACH) before call this function
 * "pid" is target Process Identify, "fd" is file descriptor of dump file
 */


int getregs(pid_t pid){
	struct reg reg;
	struct linuxreg linuxreg;
	int fd;
	unsigned long fs_base, gs_base;

	fd = open_dump_file(pid, "regs");

	memset(&reg, 0, sizeof(reg));

		
	ptrace_get_regs(pid, &reg);

	ptrace_get_fsbase(pid, &fs_base);
	ptrace_get_gsbase(pid, &gs_base);

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
	
	linuxreg.r15 = reg.r_r15;
	linuxreg.r14 = reg.r_r14;
	linuxreg.r13 = reg.r_r13;
	linuxreg.r12 = reg.r_r12;
	linuxreg.r11 = reg.r_r11;
	linuxreg.r10 = reg.r_r10;
	linuxreg.r9  = reg.r_r9;
	linuxreg.r8  = reg.r_r8;
	linuxreg.rbp = reg.r_rbp;
	linuxreg.rbx = reg.r_rbx;
	linuxreg.rax = reg.r_rax;
	linuxreg.rcx = reg.r_rcx;
	linuxreg.rdx = reg.r_rdx;
	linuxreg.rsi = reg.r_rsi;
	linuxreg.rdi = reg.r_rdi;
	linuxreg.orig_rax = reg.r_rax;
	linuxreg.rip = reg.r_rip;
	linuxreg.cs  = reg.r_cs;
      	linuxreg.eflags = reg.r_rflags;
	linuxreg.rsp = reg.r_rsp;
	linuxreg.ss  = reg.r_ss;
	linuxreg.fs_base = fs_base;
	linuxreg.gs_base = gs_base;
	linuxreg.ds  = reg.r_ds;
	linuxreg.es  = reg.r_es;
	linuxreg.fs  = reg.r_fs;
	linuxreg.gs  = reg.r_gs;	
	write(fd, &linuxreg, sizeof(linuxreg));	

	return rc;

}
