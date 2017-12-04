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

#include "parasite_syscall.c"

#define BUFSIZE 1024
#define PATHBUF 30
#define SYSCALL_ARGS 7 

#define LINUX_MAP_ANONYMOUS 0x20


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
		printf("getmem\n");
		int read_fd, dump_fd;

		read_fd = open_read_file(pid);
		dump_fd = open_dump_file(pid, "stack");
		getmem(read_fd, dump_fd, 0x7ffffffdf000);

		close(read_fd);

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
		restore_memory(pid, &orig);

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
		restore_memory(pid, &orig);
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
		
		int write_fd;
		int read_fd;

		write_fd = open_file(pid, "mem");

		read_fd = open_file(pid, "stack");
		write_mem(read_fd, write_fd, 0x7ffffffdf000);

		close(write_fd);
		ptrace(PT_DETACH, pid, (caddr_t)1, 0);
	}
	/* for debug */
	/*
	while(1){
		if(waitpid(pid, &status, 0) < 0){
			perror("waitpid");
			exit(1);
		}
		if(WIFEXITED(status)){
		}else if(WIFSTOPPED(status)){
			sleep(1);
			printf("stop PID = %d, by signal = %d\n", pid, WSTOPSIG(status));
			struct reg chreg;
			ptrace(PT_GETREGS, pid, (caddr_t)&chreg, 1);
			printf("==================================\n");
			printf("RAX: %lx\n", chreg.r_rax);
			printf("RBX: %lx\n", chreg.r_rbx);
			printf("RCX: %lx\n", chreg.r_rcx);
			printf("RDX: %lx\n", chreg.r_rdx);
			printf("RIP: %lx\n", chreg.r_rip);
			ptrace(PT_STEP, pid, (caddr_t)1, 0);
		}
	}
	*/
	return 0;
}
