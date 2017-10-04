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
	
	dprintf(fd, "RAX: %lx excuted\n", reg.r_rax);
	dprintf(fd, "RBX: %lx excuted\n", reg.r_rbx);
	dprintf(fd, "RCX: %lx excuted\n", reg.r_rcx);
	dprintf(fd, "RDX: %lx excuted\n", reg.r_rdx);
	dprintf(fd, "RSI: %lx excuted\n", reg.r_rsi);
	dprintf(fd, "RDI: %lx excuted\n", reg.r_rdi);
	dprintf(fd, "RBP: %lx excuted\n", reg.r_rbp);
	dprintf(fd, "RSP: %lx excuted\n", reg.r_rsp);
	dprintf(fd, "RIP: %lx excuted\n", reg.r_rip);
	dprintf(fd, "FLG: %lx excuted\n", reg.r_rflags);
	dprintf(fd, "R8 : %lx excuted\n", reg.r_r8);
	dprintf(fd, "R9 : %lx excuted\n", reg.r_r9);
	dprintf(fd, "R10: %lx excuted\n", reg.r_r10);
	dprintf(fd, "R11: %lx excuted\n", reg.r_r11);
	dprintf(fd, "R12: %lx excuted\n", reg.r_r12);
	dprintf(fd, "R13: %lx excuted\n", reg.r_r13);
	dprintf(fd, "R14: %lx excuted\n", reg.r_r14);
	dprintf(fd, "R15: %lx excuted\n", reg.r_r15);
	dprintf(fd, "CS : %lx excuted\n", reg.r_cs);
	dprintf(fd, "SS : %lx excuted\n", reg.r_ss);
	dprintf(fd, "DS : %lx excuted\n", reg.r_ds);
	dprintf(fd, "ES : %lx excuted\n", reg.r_es);
	dprintf(fd, "FS : %lx excuted\n", reg.r_fs);
	dprintf(fd, "GS : %lx excuted\n", reg.r_gs);

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
