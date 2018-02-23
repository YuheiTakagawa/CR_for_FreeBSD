#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/wait.h>

#include "parasite_syscall.h"
#include "ptrace.h"

#include "common.h"

#define BUILTIN_SYSCALL_SIZE 8

#define set_user_reg(pregs, name, val)	\
		(pregs->name = (val))

#define get_user_reg(pregs, name)	\
		(pregs.name)

const char code_syscall[] = {
       0x0f, 0x05,	/* syscall	*/
       0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc	/* int 3, ... */
}; 

void parasite_setup_regs(unsigned long new_ip, void *stack, struct reg *regs){
	set_user_reg(regs, r_rip, new_ip);
	if(stack)
		set_user_reg(regs, r_rsp, (unsigned long) stack);

	/* on FreeBSD, this line is stop syscall */
	//set_user_reg(regs, r_rax, -1);
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
	//ret = -1;
	return ret;

}
			


int compel_execute_syscall(pid_t pid, struct orig *orig, struct reg *regs){
	int err;
	uint8_t code_orig[BUILTIN_SYSCALL_SIZE];
	unsigned long rip = regs -> r_rip;
	orig->text = ptrace_read_i(pid, rip);
	orig->data = 0x0;
	orig->addr = 0x0;
	memcpy(code_orig, code_syscall, sizeof(code_orig));

	/* injection syscall 0xcc050f int3 */	
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

	return err;
}

void compel_syscall(pid_t pid, struct orig *orig, int nr, long *ret,
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

	compel_execute_syscall(pid, orig, &reg);
	*ret = get_user_reg(reg, r_rax);
	printf("return: %lx\n", *ret);
}

void *remote_mmap(pid_t pid, struct orig *orig, void *addr, size_t length, int prot, int flags, int fd, off_t offset){
	long map;
	int err = 0;
	
	compel_syscall(pid, orig, 9, &map,
			(unsigned long)addr, length, prot, flags, fd, offset);
	if(err < 0)
		return NULL;

	if(map == -EACCES && (prot & PROT_WRITE) && (prot & PROT_EXEC))
		return NULL;

	return (void *)map;
}

void restore_setregs(pid_t pid, struct reg orig){
	struct reg reg;
	
	ptrace_get_regs(pid, &reg);
	printf("return value(rax) : %lx\n", reg.r_rax);
		
	ptrace_set_regs(pid, &orig);
	printf("restore_registers\n");
}

void restore_memory(pid_t pid, struct orig *orig){
	ptrace_write_i(pid, orig->reg.r_rip, orig->text);
	if(orig->addr != 0x0)
	ptrace_write_d(pid, (unsigned long int)orig->addr, orig->data);
}

void restore_orig(pid_t pid, struct orig *orig){
	restore_setregs(pid, orig->reg);
	restore_memory(pid, orig);
}

