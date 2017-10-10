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

//int tracing(pid_t pid, int fd);
int getregs(pid_t pid);
//int open_dump_file(pid_t pid, char* dumptype);
/*
int main(int argc, char* argv[]){
	int fd;
	pid_t pid;
	if(argc < 2){
		printf("Usage: %s <pid to be traced>\n", argv[0]);
		exit (1);
	}
	pid = atoi(argv[1]);

	tracing(pid, fd);
}

int open_dump_file(pid_t pid, char *dumptype){

	int fd;
	char filepath[30] = {'\0'};

	snprintf(filepath, sizeof(filepath), "/dump/%d_%s.img", pid, dumptype);
	fd = open(filepath, O_WRONLY | O_CREAT);
	if(fd < 0){
		perror("open");
		exit(1);
	}
	return fd;

}
*/
/*
 * get register status
 * must run  ptrace(PT_ATTACH) before call this function
 * "pid" is target Process Identify, "fd" is file descriptor of dump file
 */

int getregs(pid_t pid){
	struct reg reg;
	int rc;
	int fd;

	fd = open_dump_file(pid, "regs");

	memset(&reg, 0, sizeof(reg));

		
	rc = ptrace(PT_GETREGS, pid, (caddr_t)&reg, 0);
	if(rc < 0){
		perror("ptrace");
		exit (1);
	}
	printf("RAX: %lx excuted\n", reg.r_rax);
	printf("RBX: %lx excuted\n", reg.r_rbx);
	printf("RCX: %lx excuted\n", reg.r_rcx);
	printf("RDX: %lx excuted\n", reg.r_rdx);
	printf("RSI: %lx excuted\n", reg.r_rsi);
	printf("RDI: %lx excuted\n", reg.r_rdi);
	printf("RBP: %lx excuted\n", reg.r_rbp);
	printf("RSP: %lx excuted\n", reg.r_rsp);
	printf("RIP: %lx excuted\n", reg.r_rip);
	printf("FLG: %lx excuted\n", reg.r_rflags);
	printf("R8 : %lx excuted\n", reg.r_r8);
	printf("R9 : %lx excuted\n", reg.r_r9);
	printf("R10: %lx excuted\n", reg.r_r10);
	printf("R11: %lx excuted\n", reg.r_r11);
	printf("R12: %lx excuted\n", reg.r_r12);
	printf("R13: %lx excuted\n", reg.r_r13);
	printf("R14: %lx excuted\n", reg.r_r14);
	printf("R15: %lx excuted\n", reg.r_r15);
	printf("CS : %lx excuted\n", reg.r_cs);
	printf("SS : %lx excuted\n", reg.r_ss);
	printf("DS : %x excuted\n", reg.r_ds);
	printf("ES : %x excuted\n", reg.r_es);
	printf("FS : %x excuted\n", reg.r_fs);

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
