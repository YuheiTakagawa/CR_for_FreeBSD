#include <stdio.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "fds.c"
#include "register.c"
#include "setmem.c"
#include "ptrace.h"
#include "parasite_syscall.h"
#include "breakpoint.c"

#include "common.h"

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

int restore_fork(int filePid, char *exec_path){
	pid_t pid;
	int fd;
	int i;
	struct restore_fd_struct fds[1024];
	read_fd_list(filePid, fds);
	for(i = 0; fds[i].fd != -2 ; i++){
		printf("fd:%d, off:%ld, path:%s\n", fds[i].fd, fds[i].offset, fds[i].path);
		/* if restore tty info, have to implement restoring ttys*/
		if(strstr(fds[i].path, "/dev/pts") == NULL)
			fd = prepare_restore_files(fds[i].path, fds[i].fd, fds[i].offset);
	}
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
	struct orig orig;
	struct remap_vm_struct revm[BUFSIZE];

	if(argc < 3){
		printf("Usage: %s <path> <file pid> <stack addr> <file offset>\n", argv[0]);
		exit(1);
	}

	filepath = argv[1];
	filePid = atoi(argv[2]);

	//fds.offset = strtol(argv[4], NULL, 16);
	printf("CMD : %s\n", argv[1]);
	printf("PPID: %d\n", getpid());
	printf("Restore file: %d\n", filePid); 

	//fds.path = "/dump/hello";
	//fds.fd = 3;

	pid = restore_fork(filePid, filepath);
	insert_breakpoint(pid, filepath);
//	remap_vm(pid, stack_addr, stack_size, &orig);
	remap_vm(pid, filePid, revm, &orig);
			waitpro(pid, &status);
			//printf("sig stopped: %d\n", WSTOPSIG(status));
					setmems(pid, filePid, revm);
					setregs(pid, filePid);
					ptrace_cont(pid);
			waitpro(pid, &status);
			print_regs(pid);

		while(1){}
	return 0;
}

