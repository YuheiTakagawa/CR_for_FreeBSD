#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#define BUFSIZE 1024
#define PATHBUF 30
#define SYSCALL_ARGS 7 

long code = 0xcc050f;

struct orig{
	long text;
	long data;
	char *addr;
	struct reg reg;
};

#define LINUX_MAP_ANONYMOUS 0x20

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
	ptrace(PT_WRITE_I, pid, (caddr_t)orig->reg.r_rip, orig->text);
	ptrace(PT_WRITE_I, pid, (caddr_t)orig->addr, orig->data);
	
}

int main(int argc, char* argv[]){
	int pid;
	int status;
	int flag = 0;
	
	char *mem;
	struct orig orig;
	pid = atoi(argv[1]);

	if(ptrace(PT_ATTACH, pid, NULL, 0) < 0){
		perror("ptrace(ATTACH)");
		exit(1);
	}
	printf("Attached PID:%d\n", pid);

	if(waitpid(pid, &status, 0) < 0){
		perror("waitpid");
		exit(1);
	}

	if(WIFEXITED(status)){
	}else if (WIFSTOPPED(status)){
		printf("stop PID = %d, by signal = %d\n", pid, WSTOPSIG(status));
		printf("==================\n");
		printf("mmap\n");
		inject_syscall(pid, &orig, SYSCALL_ARGS, 9, 0x0, 
				0x21000, PROT_READ | PROT_WRITE | PROT_EXEC,
			       	MAP_PRIVATE | LINUX_MAP_ANONYMOUS, 0x0, 0x0);
		ptrace(PT_CONTINUE, pid, (caddr_t)1, 0);
	}

	if(waitpid(pid, &status, 0) < 0){
		perror("waitpid");
		exit(1);
	}

	if(WIFEXITED(status)){
	}else if (WIFSTOPPED(status)){
		printf("stop PID = %d, by signal = %d\n", pid, WSTOPSIG(status));
		restore_setregs(pid, orig.reg);

		printf("munmap\n");
		inject_syscall(pid, &orig, SYSCALL_ARGS, 11, 0x7ffffffdf000, 
				0x21000, 0x0, 0x0, 0x0, 0x0);
		ptrace(PT_CONTINUE, pid, (caddr_t)1, 0);
	}

	if(waitpid(pid, &status, 0) < 0){
		perror("waitpid");
		exit(1);
	}

	if(WIFEXITED(status)){
	}else if(WIFSTOPPED(status)){
		printf("stop PID = %d, by signal = %d\n", pid, WSTOPSIG(status));

		restore_setregs(pid, orig.reg);
		inject_syscall(pid, &orig, SYSCALL_ARGS, 9, 0x7ffffffdf000,
				0x21000, PROT_READ | PROT_WRITE | PROT_EXEC,
				MAP_PRIVATE | LINUX_MAP_ANONYMOUS, 0x0, 0x0);
		ptrace(PT_CONTINUE, pid, (caddr_t)1, 0);
	}
	if(waitpid(pid, &status, 0) < 0){
		perror("waitpid");
		exit(1);
	}
	if(WIFEXITED(status)){
	}else if(WIFSTOPPED(status)){
		printf("stop PID = %d, by signal = %d\n", pid, WSTOPSIG(status));
		restore_setregs(pid, orig.reg);
		restore_memory(pid, &orig);
		//ptrace(PT_DETACH, pid, (caddr_t)1, 0);
		while(1){}
	}

	return 0;
}
