#ifndef PARASITE_SYSCALL
#define PARASITE_SYSCALL

#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <stdint.h>

#include "getmem.c"
#include "setmem.c"
#include "ptrace.h"

#define BUFSIZE 1024
#define PATHBUF 30
#define SYSCALL_ARGS 7 

#define LINUX_MAP_ANONYMOUS 0x20

long code = 0xcc050f;

struct orig{
	long text;
	long data;
	char *addr;
	struct user_regs_struct reg;
};

void inject_syscall_regs(int pid, struct orig *orig, int nr, 
		unsigned long arg1,
		unsigned long arg2,
		unsigned long arg3,
		unsigned long arg4,
		unsigned long arg5,
		unsigned long arg6)
{
	struct user_regs_struct reg;	
	ptrace_get_regs(pid, &reg);
	orig->reg = reg;

	reg.rax = (uint64_t)nr;
	reg.rdi = arg1;
	reg.rsi = arg2;
	reg.rdx = arg3;
	reg.r10 = arg4;
	reg.r8  = arg5;
	reg.r9  = arg6;

	ptrace_set_regs(pid, &reg);
}

void inject_syscall_mem(int pid, struct orig *orig, unsigned long rip){
	orig->text = ptrace_read_i(pid, rip);
	orig->data = 0x0;
	orig->addr = 0x0;

	/* injection syscall 0xcc050f */	
	ptrace_write_i(pid, rip, code);
	/******************************/
}

void inject_syscall_buf(int pid, struct orig *orig, char *addr){
	int *tmp = malloc(sizeof(int));
	orig->data = ptrace_read_i(pid, (unsigned long int) addr);
	orig->addr = addr;
	/* injection syscall buf */
	for(int i = 0; i < strlen(addr) / 4 + 1; i++){
		memset(tmp, 0, 4 + 1);
		memcpy(tmp, addr + i * 4, 4);
		ptrace_write_i(pid, (unsigned long int)addr + i * 4, *tmp);
	}
	/*************************/
	free(tmp);
	printf("orig_text: %lx\n", orig->text);
	printf("orig_data: %lx\n", orig->data);
}

void inject_syscall(int pid, struct orig *orig, char *addr, int num, ...){
	va_list list;
	unsigned long arg[num];
	
	va_start(list, num);
	for(int i = 0; i < num; i++){
		arg[i] = va_arg(list, unsigned long);
	}
	va_end(list);
	inject_syscall_regs(pid, orig, arg[0], arg[1],
		       	arg[2], arg[3], arg[4], arg[5], arg[6]);
	inject_syscall_mem(pid, orig, orig->reg.rip);
	if(addr != NULL)
		inject_syscall_buf(pid, orig, addr);
}

void restore_setregs(int pid, struct user_regs_struct orig){
	struct user_regs_struct reg;
	
	ptrace_get_regs(pid, &reg);
	printf("return value(rax) : %llx\n", reg.rax);
		
	ptrace_set_regs(pid, &orig);
	printf("restore_registers\n");
}

void restore_memory(int pid, struct orig *orig){
	printf("orig_text: %lx\n", orig->text);
	ptrace_write_i(pid, orig->reg.rip, orig->text);
	if(orig->addr != 0x0)
	ptrace_write_d(pid, (unsigned long int)orig->addr, orig->data);
}

void restore_orig(int pid, struct orig *orig){
	restore_setregs(pid, orig->reg);
	restore_memory(pid, orig);
}

#endif