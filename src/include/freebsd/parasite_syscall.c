#ifndef PARASITE_SYSCALL
#define PARASITE_SYSCALL

#include <unistd.h>
#include <stdarg.h>
#include <string.h>

#include "getmem.c"
#include "setmem.c"
#include "ptrace.h"

#define BUFSIZE 1024
#define PATHBUF 30
#define SYSCALL_ARGS 7 
#define BUILTIN_SYSCALL_SIZE 8

#define LINUX_MAP_ANONYMOUS 0x20

#define set_user_reg(pregs, name, val)	\
		pregs->name = (val)


const char  code_syscall[] = {
       0x0f, 0x05,	/* syscall	*/
       0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc	/* int 3, ... */
}; 

struct orig{
	long text;
	long data;
	char *addr;
	struct reg reg;
};

void restore_orig(pid_t, struct orig*);

void inject_syscall_regs(int pid, struct orig *orig, int nr, 
		unsigned long arg1,
		unsigned long arg2,
		unsigned long arg3,
		unsigned long arg4,
		unsigned long arg5,
		unsigned long arg6)
{
	struct reg reg;	
	ptrace_get_regs(pid, &reg);
	orig->reg = reg;

	reg.r_rax = (uint64_t)nr;
	reg.r_rdi = arg1;
	reg.r_rsi = arg2;
	reg.r_rdx = arg3;
	reg.r_r10 = arg4;
	reg.r_r8  = arg5;
	reg.r_r9  = arg6;

	ptrace_set_regs(pid, &reg);
}

//int execute_syscall(struct regs *regs, 

void parasite_setup_regs(unsigned long new_ip, void *stack, struct reg *regs){
	set_user_reg(regs, r_rip, new_ip);
	if(stack)
		set_user_reg(regs, r_rsp, (unsigned long) stack);

	set_user_reg(regs, r_rax, -1);
}


static int parasite_run(pid_t pid, int cmd, unsigned long ip, void *stack, struct reg *regs, struct orig *orig){
	
	parasite_setup_regs(ip, stack, regs);
	if (ptrace_set_regs(pid, regs)) {
	}

	if (ptrace(cmd, pid, (caddr_t)1, 0)) {
	}

	return 0;
}

static int parasite_trap(pid_t pid, struct reg *regs, struct orig *orig){
	int status;
	int ret = -1;

	if(wait4(pid, &status, 0, NULL) != pid){
		goto err;
	}

	if(!WIFSTOPPED(status)){
		goto err;
	}

	if(ptrace_get_regs(pid, regs)){
		goto err;
	}

	if(WSTOPSIG(status) != SIGTRAP){
		goto err;
	}

	ret = 0;
err:
	restore_orig(pid, orig);
	ret = -1;
	return ret;

}
			


int inject_syscall_mem(int pid, struct orig *orig, struct reg *regs){
	int err;
	uint8_t code_orig[BUILTIN_SYSCALL_SIZE];
	unsigned long rip = regs -> r_rip;
	orig->text = ptrace_read_i(pid, rip);
	orig->data = 0x0;
	orig->addr = 0x0;
	memcpy(code_orig, code_syscall, sizeof(code_orig));

	/* injection syscall 0xcc050f */	
	//ptrace_write_i(pid, rip, code_syscall);
	if(ptrace_swap_area(pid, (void *)rip, (void *)code_orig, sizeof(code_orig))){
		return -1;
	}

	err = parasite_run(pid, PT_CONTINUE, rip, 0, regs, orig);
	if (!err)
		err = parasite_trap(pid, regs, orig);

	if (ptrace_poke_area(pid, (void *)code_orig,
			     (void *)rip, sizeof(code_orig))) {
		err = -1;
	}

	/******************************/
	return err;
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
	inject_syscall_mem(pid, orig, &orig->reg);
	if(addr != NULL)
		inject_syscall_buf(pid, orig, addr);
}

void restore_setregs(int pid, struct reg orig){
	struct reg reg;
	
	ptrace_get_regs(pid, &reg);
	printf("return value(rax) : %lx\n", reg.r_rax);
		
	ptrace_set_regs(pid, &orig);
	printf("restore_registers\n");
}

void restore_memory(int pid, struct orig *orig){
	printf("orig_text: %lx\n", orig->text);
	ptrace_write_i(pid, orig->reg.r_rip, orig->text);
	if(orig->addr != 0x0)
	ptrace_write_d(pid, (unsigned long int)orig->addr, orig->data);
}

void restore_orig(int pid, struct orig *orig){
	restore_setregs(pid, orig->reg);
	restore_memory(pid, orig);
}

#endif
