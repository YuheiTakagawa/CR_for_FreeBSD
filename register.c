#include <sys/types.h>

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


int setregs(int pid, pid_t filePid){
	struct reg reg;
	struct linuxreg linuxreg;
	int fd;

	memset(&reg, 0, sizeof(reg));
	fd = open_file(filePid, "regs");
	read(fd, &linuxreg, sizeof(linuxreg));

	ptrace_get_regs(pid, &reg);

	reg.r_rax = linuxreg.orig_rax;
	reg.r_rbx = linuxreg.rbx;
	reg.r_rcx = linuxreg.rcx;
	reg.r_rdx = linuxreg.rdx;
	reg.r_rsi = linuxreg.rsi;
	reg.r_rdi = linuxreg.rdi;
	reg.r_rbp = linuxreg.rbp;
	reg.r_rsp = linuxreg.rsp;
	reg.r_rip = linuxreg.rip;
	reg.r_rflags = linuxreg.eflags;
	reg.r_r8 = linuxreg.r8;
	reg.r_r9 = linuxreg.r9;
	reg.r_r10 = linuxreg.r10;
	reg.r_r11 = linuxreg.r11;
	reg.r_r12 = linuxreg.r12;
	reg.r_r13 = linuxreg.r13;
	reg.r_r14 = linuxreg.r14;
	reg.r_r15 = linuxreg.r15;

/*      reg.r_cs = 0x43;
	reg.r_ss = 0x3b;
	reg.r_ds = 0x0;
	reg.r_es = 0x0;
	reg.r_fs = 0x0;
	reg.r_gs = 0x0;
*/      
	if(ptrace_set_regs(pid, &reg) < 0){
	perror("ptrace(PT_SETREGS, ...)");
	exit(1);
	}
	return 0;
}



