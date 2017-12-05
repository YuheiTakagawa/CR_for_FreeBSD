#ifndef PARASITE_SYSCALL
#define PARASITE_SYSCALL

#include <unistd.h>
#include <stdarg.h>

#include "getmem.c"
#include "setmem.c"

#define BUFSIZE 1024
#define PATHBUF 30
#define SYSCALL_ARGS 7 

#define LINUX_MAP_ANONYMOUS 0x20

long code = 0xcc050f;

struct orig{
	long text;
	long data;
	char *addr;
	struct reg reg;
};

void inject_syscall_regs(int pid, struct orig *orig, int nr, 
		unsigned long arg1,
		unsigned long arg2,
		unsigned long arg3,
		unsigned long arg4,
		unsigned long arg5,
		unsigned long arg6)
{
	struct reg reg;	
	ptrace(PT_GETREGS, pid, (caddr_t)&reg, 1);
	orig->reg = reg;

	reg.r_rax = (uint64_t)nr;
	reg.r_rdi = arg1;
	reg.r_rsi = arg2;
	reg.r_rdx = arg3;
	reg.r_r10 = arg4;
	reg.r_r8  = arg5;
	reg.r_r9  = arg6;

	ptrace(PT_SETREGS, pid, (caddr_t)&reg, 1);
}

void inject_syscall_mem(int pid, struct orig *orig, unsigned long rip){
	orig->text = ptrace(PT_READ_I, pid, (caddr_t)rip, 0);
	orig->data = 0x0;
	orig->addr = 0x0;

	/* injection syscall 0xcc050f */	
	if(ptrace(PT_WRITE_I, pid, (caddr_t)rip, code) < 0){
		perror("ptrace(WRITE_I)");
		exit(1);
	}
	/******************************/
}

void inject_syscall(int pid, struct orig *orig, int num, ...){
	va_list list;
	unsigned long arg[num];
	
	va_start(list, num);
	for(int i = 0; i < num; i++){
		arg[i] = va_arg(list, unsigned long);
	}
	va_end(list);
	inject_syscall_regs(pid, orig, arg[0], arg[1],
		       	arg[2], arg[3], arg[4], arg[5], arg[6]);
	inject_syscall_mem(pid, orig, orig->reg.r_rip);
}

void restore_setregs(int pid, struct reg orig){
	struct reg reg;
	
	ptrace(PT_GETREGS, pid, (caddr_t)&reg, 1);
	printf("return value(rax) : %lx\n", reg.r_rax);
		
	ptrace(PT_SETREGS, pid, (caddr_t)&orig, 1);
	printf("restore_registers\n");
}

void restore_memory(int pid, struct orig *orig){
	printf("orig_text: %lx\n", orig->text);
	ptrace(PT_WRITE_I, pid, (caddr_t)orig->reg.r_rip, orig->text);
	//ptrace(PT_WRITE_I, pid, (caddr_t)orig->addr, orig->data);
	
}

#endif
