#ifndef REGISTER
#define REGISTER

#include <sys/types.h>
#include <sys/user.h>
#include <sys/reg.h>


#include "ptrace.h"
#include "files.h"

struct linuxreg{
	unsigned long int r15;
	unsigned long int r14;
	unsigned long int r13;
	unsigned long int r12;
	unsigned long int rbp;
	unsigned long int rbx;
	unsigned long int r11;
	unsigned long int r10;
	unsigned long int r9;
	unsigned long int r8;
	unsigned long int rax;
	unsigned long int rcx;
	unsigned long int rdx;
	unsigned long int rsi;
	unsigned long int rdi;
	unsigned long int orig_rax;
	unsigned long int rip;
	unsigned long int cs;
	unsigned long int eflags;
	unsigned long int rsp;
	unsigned long int ss;
	unsigned long int fs_base;
	unsigned long int gs_base;
	unsigned long int ds;
	unsigned long int es;
	unsigned long int fs;
	unsigned long int gs;
};

int check_rip_syscall(int pid, unsigned long int rip){
	
	printf("rip code:%x\n", ptrace_read_i(pid, rip));

	return 1;
}

void print_regs(int pid){
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
        //printf("TRA: %x excuted\n", reg.trapno);
        printf("CS : %llx excuted\n", reg.cs);
        printf("SS : %llx excuted\n", reg.ss);
        printf("DS : %llx excuted\n", reg.ds);
        printf("ES : %llx excuted\n", reg.es);
        printf("FS : %llx excuted\n", reg.fs);
        printf("GS : %llx excuted\n", reg.gs);

}
int setregs(int pid, pid_t filePid){
	struct user_regs_struct reg;
	struct linuxreg linuxreg;
	int fd;

	memset(&reg, 0, sizeof(reg));
	fd = open_file(filePid, "regs");
	read(fd, &linuxreg, sizeof(linuxreg));

	ptrace_get_regs(pid, &reg);

	reg.orig_rax = linuxreg.orig_rax;
	reg.rax = linuxreg.rax;
	reg.rbx = linuxreg.rbx;
	reg.rcx = linuxreg.rcx;
	reg.rdx = linuxreg.rdx;
	reg.rsi = linuxreg.rsi;
	reg.rdi = linuxreg.rdi;
	reg.rbp = linuxreg.rbp;
	reg.rsp = linuxreg.rsp;
	reg.rip = linuxreg.rip;
	reg.eflags = linuxreg.eflags;
	reg.r8 = linuxreg.r8;
	reg.r9 = linuxreg.r9;
	reg.r10 = linuxreg.r10;
	reg.r11 = linuxreg.r11;
	reg.r12 = linuxreg.r12;
	reg.r13 = linuxreg.r13;
	reg.r14 = linuxreg.r14;
	reg.r15 = linuxreg.r15;
/*
	reg.cs = 0x33;
	reg.ss = 0x2b;
	reg.ds = 0x0;
	reg.es = 0x0;
	reg.fs = 0x0;
	reg.gs = 0x0;
  */    
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
	struct linuxreg linuxreg;
	int fd;
	unsigned long fs_base, gs_base;

	fd = open_dump_file(pid, "regs");

	memset(&reg, 0, sizeof(reg));

	ptrace_get_regs(pid, &reg);

	//ptrace_get_fsbase(pid, &fs_base);
	//ptrace_get_gsbase(pid, &gs_base);


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
	//printf("TRA: %x excuted\n", reg.trapno);
	printf("CS : %llx excuted\n", reg.cs);
	printf("SS : %llx excuted\n", reg.ss);
	printf("DS : %llx excuted\n", reg.ds);
	printf("ES : %llx excuted\n", reg.es);
	printf("FS : %llx excuted\n", reg.fs);
	printf("GS : %llx excuted\n", reg.gs);
	printf("FSB: %llx excuted\n", reg.fs_base);
	printf("GSB: %llx excuted\n", reg.gs_base);

	linuxreg.r15 = reg.r15;
	linuxreg.r14 = reg.r14;
	linuxreg.r13 = reg.r13;
	linuxreg.r12 = reg.r12;
	linuxreg.r11 = reg.r11;
	linuxreg.r10 = reg.r10;
	linuxreg.r9  = reg.r9;
	linuxreg.r8  = reg.r8;
	linuxreg.rbp = reg.rbp;
	linuxreg.rbx = reg.rbx;
	linuxreg.rax = reg.rax;
	linuxreg.rcx = reg.rcx;
	linuxreg.rdx = reg.rdx;
	linuxreg.rsi = reg.rsi;
	linuxreg.rdi = reg.rdi;
	linuxreg.orig_rax = reg.orig_rax;
	linuxreg.rip = reg.rip;
	linuxreg.cs  = reg.cs;
	linuxreg.eflags = reg.eflags;
	linuxreg.rsp = reg.rsp;
	linuxreg.ss  = reg.ss;
	linuxreg.fs_base = reg.fs_base;
	linuxreg.gs_base = reg.gs_base;
	linuxreg.ds  = reg.ds;
	linuxreg.es  = reg.es;
	linuxreg.fs  = reg.fs;
	linuxreg.gs  = reg.gs;
	write(fd, &linuxreg, sizeof(linuxreg));

	return 0;
}

#endif
