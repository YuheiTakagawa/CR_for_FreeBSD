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
#include <sys/user.h>
#include <sys/reg.h>

int getregs(pid_t pid);
/*
 * get register status
 * must run  ptrace(PT_ATTACH) before call this function
 * "pid" is target Process Identify, "fd" is file descriptor of dump file
 */

int getregs(pid_t pid){
	struct user_regs_struct reg;
	int rc;
	int fd;

	fd = open_dump_file(pid, "regs");

	memset(&reg, 0, sizeof(reg));

		
	rc = ptrace(PTRACE_GETREGS, pid, 0, &reg);
	if(rc < 0){
		perror("ptrace(GETREGS)");
		exit (1);
	}
	printf("OAX: %llx excuted\n", reg.orig_rax);
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
	printf("FSB: %llx excuted\n", reg.fs_base);
	printf("GSB: %llx excuted\n", reg.gs_base);
	printf("R8 : %llx excuted\n", reg.r8);
	printf("R9 : %llx excuted\n", reg.r9);
	printf("R10: %llx excuted\n", reg.r10);
	printf("R11: %llx excuted\n", reg.r11);
	printf("R12: %llx excuted\n", reg.r12);
	printf("R13: %llx excuted\n", reg.r13);
	printf("R14: %llx excuted\n", reg.r14);
	printf("R15: %llx excuted\n", reg.r15);
	printf("CS : %llx excuted\n", reg.cs);
	printf("SS : %llx excuted\n", reg.ss);
	printf("DS : %llx excuted\n", reg.ds);
	printf("ES : %llx excuted\n", reg.es);
	printf("FS : %llx excuted\n", reg.fs);

	write(fd, &reg, sizeof(reg));
	
	return rc;

}
/*
int tracing(pid_t pid, int fd){
	int status;
	int rc;
	rc = ptrace(PT_ATTACH, pid, NULL, 0);
	if(rc < 0){
		perror("ptrace");
		exit (1);
	}
	waitpid(pid, &status, 0);
	if(WIFEXITED(status)){
	} else if (WIFSTOPPED(status)){
		printf("stop %d\n", WSTOPSIG(status));
		getregs(pid);
	}

	ptrace(PT_DETACH, pid, (caddr_t)1, 0);
	printf("Process detached\n");
	return 0;
}
*/
