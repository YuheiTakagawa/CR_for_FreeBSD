#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdint.h>
#include <sys/wait.h>
#include <sys/user.h>

#include "parasite_syscall.h"
#include "ptrace.h"

#include "common.h"

#define set_user_reg(pregs, name, val)	\
		(pregs->name = (val))

#define get_user_reg(pregs, name)	\
		(pregs.name)

const char code_syscall[] = {
       0x0f, 0x05,	/* syscall	*/
       0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc	/* int 3, ... */
}; 

void parasite_setup_regs(unsigned long new_ip, void *stack, struct user_regs_struct *regs){
	set_user_reg(regs, rip, new_ip);
	if(stack)
		set_user_reg(regs, rsp, (unsigned long) stack);

	/* on FreeBSD, this line is stop syscall */
	//set_user_reg(regs, rax, -1);
}


static int parasite_run(pid_t pid, int cmd, unsigned long ip, void *stack, struct user_regs_struct *regs, struct orig *orig){
	
	parasite_setup_regs(ip, stack, regs);
	if (ptrace_set_regs(pid, regs)) {
	}

	if (ptrace(cmd, pid, 1, 0)) {
	}

	return 0;
}

static int parasite_trap(pid_t pid, struct user_regs_struct *regs, struct orig *orig){
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
			


int compel_execute_syscall(pid_t pid, struct orig *orig, struct user_regs_struct *regs){
	int err;
	uint8_t code_orig[BUILTIN_SYSCALL_SIZE];
	unsigned long rip = regs -> rip;
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
	struct user_regs_struct reg;	
	ptrace_get_regs(pid, &reg);
	orig->reg = reg;

	reg.orig_rax = (uint64_t)nr;
	reg.rdi = arg1;
	reg.rsi = arg2;
	reg.rdx = arg3;
	reg.r10 = arg4;
	reg.r8  = arg5;
	reg.r9  = arg6;

	compel_execute_syscall(pid, orig, &reg);
	*ret = get_user_reg(reg, rax);
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

void restore_setregs(pid_t pid, struct user_regs_struct orig){
	struct user_regs_struct reg;
	
	ptrace_get_regs(pid, &reg);
	printf("return value(rax) : %llx\n", reg.rax);
		
	ptrace_set_regs(pid, &orig);
	printf("restore_registers\n");
}

void restore_memory(pid_t pid, struct orig *orig){
	ptrace_write_i(pid, orig->reg.rip, orig->text);
	if(orig->addr != 0x0)
	ptrace_write_d(pid, (unsigned long int)orig->addr, orig->data);
}

void restore_orig(pid_t pid, struct orig *orig){
	restore_setregs(pid, orig->reg);
	restore_memory(pid, orig);
}

