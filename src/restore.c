#include <stdio.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <sys/mman.h>

#include "register.c"
#include "setmem.c"
#include "ptrace.h"
#include "parasite_syscall.c"
#include "getmap.c"
#include "breakpoint.c"

#define BUFSIZE 1024
#define PATHBUF 30


struct restore_fd_struct{
	char *path;
	int fd;
	off_t offset;
};

int target(char *path, char* argv[]);

int target(char *path, char *argv[]){
	char *exec[] = {path, NULL};
	int ret;
	printf("CPID: %d\n", getpid());
	printf("command: %s\n", exec[0]);
	ptrace_traceme();

	ret = execvp(exec[0], exec);
	perror("execvp");
	exit(ret);
}

int prepare_restore_files(char *path, int fd, off_t foff){
	printf("PATH:%s\n", path);
	int tmp = open("/dump/hello", O_RDWR);
	if(fd != tmp){
		fd = dup2(tmp, fd);
		close(tmp);
	}
	lseek(fd, foff, SEEK_SET);
	return fd;	
}

int restore_fork(char *exec_path, struct restore_fd_struct *fds){
	pid_t pid;
	int fd;
	fd = prepare_restore_files(fds->path, fds->fd, fds->offset);
	printf("get fd: %d\n", fd);

	pid = fork();
	if(pid < 0){
		perror("FORK");
		exit(1);
	}
	if(pid != 0){
		close(fd);
		return pid;
	}
	target(exec_path, NULL);
	return 0;
}

int main(int argc, char* argv[]){
	int pid, filePid;
	int status;
	char *filepath;
	unsigned long int stack_addr;
	unsigned long int stack_size;
	struct restore_fd_struct fds;
	struct orig orig;

	if(argc < 5){
		printf("Usage: %s <path> <file pid> <stack addr> <file offset>\n", argv[0]);
		exit(1);
	}

	filepath = argv[1];
	filePid = atoi(argv[2]);

	stack_addr = strtol(argv[3], NULL, 16);
	stack_size = 0x20000;
	if(stack_addr != 0x7ffffffdf000){
		stack_size = 0x21000;
	}
	fds.offset = strtol(argv[4], NULL, 16);
	printf("CMD : %s\n", argv[1]);
	printf("PPID: %d\n", getpid());
	printf("Restore file: %d\n", filePid); 

	fds.path = "/dump/hello";
	fds.fd = 3;

	pid = restore_fork(filepath, &fds);
	remap_vm(pid, stack_addr, stack_size, &orig);
			waitpro(pid, &status);
					//restore_orig(pid, &orig);
					setmems(pid, filePid, stack_addr);
					setregs(pid, filePid);
					printf("aaaaaaaaaaaa\n");
					ptrace_cont(pid);
			waitpro(pid, &status);
			print_regs(pid);

		while(1){}
	return 0;
}

