#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>

#include "emulate.h"
#include "files.h"
#include "ptrace.h"
#include "register.h"
#include "image.h"
#include "imgset.h"
#include "images/core.pb-c.h"

int check_rip_syscall(pid_t pid, unsigned long int rip){
	
	printf("rip code:%x\n", ptrace_read_i(pid, rip));

	return 1;
}

void __print_regs(struct reg *reg){
	printf("RAX: %lx excuted\n", reg->r_rax);
        printf("RBX: %lx excuted\n", reg->r_rbx);
        printf("RCX: %lx excuted\n", reg->r_rcx);
        printf("RDX: %lx excuted\n", reg->r_rdx);
        printf("RSI: %lx excuted\n", reg->r_rsi);
        printf("RDI: %lx excuted\n", reg->r_rdi);
        printf("RBP: %lx excuted\n", reg->r_rbp);
        printf("RSP: %lx excuted\n", reg->r_rsp);
        printf("RIP: %lx excuted\n", reg->r_rip);
        printf("FLG: %lx excuted\n", reg->r_rflags);
        printf("R8 : %lx excuted\n", reg->r_r8);
        printf("R9 : %lx excuted\n", reg->r_r9);
        printf("R10: %lx excuted\n", reg->r_r10);
        printf("R11: %lx excuted\n", reg->r_r11);
        printf("R12: %lx excuted\n", reg->r_r12);
        printf("R13: %lx excuted\n", reg->r_r13);
        printf("R14: %lx excuted\n", reg->r_r14);
        printf("R15: %lx excuted\n", reg->r_r15);
        printf("TRA: %x excuted\n", reg->r_trapno);
        printf("CS : %lx excuted\n", reg->r_cs);
        printf("SS : %lx excuted\n", reg->r_ss);
        printf("DS : %x excuted\n", reg->r_ds);
        printf("ES : %x excuted\n", reg->r_es);
        printf("FS : %x excuted\n", reg->r_fs);
        printf("GS : %x excuted\n", reg->r_gs);
}


void print_regs(pid_t pid){
	struct reg reg;
	ptrace_get_regs(pid, &reg);
	__print_regs(&reg);
}
#define CEREGS(ce, reg) ce->thread_info_gpregs->reg
int setregs(pid_t pid, CoreEntry *ce){
	struct reg reg;
	struct linuxreg *linuxreg;
	int fd;
	unsigned long int fs_base;


	memset(&reg, 0, sizeof(reg));
	//linuxreg = (struct linuxreg *)malloc(sizeof(struct linuxreg));
	linuxreg = (struct linuxreg *)&ce->thread_info->gpregs->r15;
	printf("OAX: %lx excuted\n", linuxreg->rax);
//	fd = open_file(93585, "regs");
//	read(fd, linuxreg, sizeof(struct linuxreg));

	ptrace_get_regs(pid, &reg);
	printf("rax %lx\n", linuxreg->orig_rax);

	reg.r_rax = linuxreg->orig_rax;
//	reg.r_rax = linuxreg->rax;
//	reg.r_rax = 0xfffffffffffff000;
	reg.r_rbx = linuxreg->rbx;
	reg.r_rcx = linuxreg->rcx;
	reg.r_rdx = linuxreg->rdx;
	reg.r_rsi = linuxreg->rsi;
	reg.r_rdi = linuxreg->rdi;
	reg.r_rbp = linuxreg->rbp;
	reg.r_rsp = linuxreg->rsp;
	reg.r_rip = linuxreg->rip-0x2;
	reg.r_rflags = linuxreg->eflags;
	reg.r_r8 = linuxreg->r8;
	reg.r_r9 = linuxreg->r9;
	reg.r_r10 = linuxreg->r10;
	reg.r_r11 = linuxreg->r11;
	reg.r_r12 = linuxreg->r12;
	reg.r_r13 = linuxreg->r13;
	reg.r_r14 = linuxreg->r14;
	reg.r_r15 = linuxreg->r15;
	fs_base = linuxreg->fs_base;

/*      reg.r_cs = 0x43;
	reg.r_ss = 0x3b;
	reg.r_ds = 0x0;
	reg.r_es = 0x0;
	reg.r_fs = 0x0;
	reg.r_gs = 0x0;
*/      
	
	printf("fs_base %lx\n", fs_base);
	check_rip_syscall(pid, reg.r_rip);
	ptrace_set_fsbase(pid, &fs_base);

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
	struct reg reg;
	struct linuxreg linuxreg;
	int fd;
	unsigned long fs_base, gs_base;

	fd = open_dump_file(pid, "regs");

	memset(&reg, 0, sizeof(reg));

	ptrace_get_regs(pid, &reg);

	ptrace_get_fsbase(pid, &fs_base);
	ptrace_get_gsbase(pid, &gs_base);


	__print_regs(&reg);
	printf("FSB: %lx excuted\n", fs_base);
	printf("GSB: %lx excuted\n", gs_base);

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

	return 0;
}
