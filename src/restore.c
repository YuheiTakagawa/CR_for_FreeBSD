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

#include "register.c"
#include "setmem.c"
#include "ptrace.h"
#include "parasite_syscall.c"
#include "breakpoint.c"

#define BUFSIZE 1024
#define PATHBUF 30


struct restore_fd_struct{
	char path[BUFSIZE];
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
	int tmp = open(path, O_RDWR);
	if(fd != tmp){
		fd = dup2(tmp, fd);
		close(tmp);
	}
	lseek(fd, foff, SEEK_SET);
	return fd;	
}

void read_fd_list(pid_t filePid, struct restore_fd_struct *fds){
	int read_fd;
	char buf[BUFSIZE];
	int i = 0;
	read_fd = open_file(filePid, "fds");
	while(read(read_fd, &buf[i++], sizeof(char))){
		if(buf[i-1] == '\n'){
			buf[i-1] = '\0';
			fds->fd = atoi(strtok(buf, ","));
			fds->offset = atoi(strtok(NULL, ","));
			strncpy(fds->path, strtok(NULL, "\0"), i);
			fds++;
			i = 0;
		}
	}
	close(read_fd);
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
	unsigned long int stack_addr;
	unsigned long int stack_size;
	struct orig orig;

	if(argc < 4){
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
	//fds.offset = strtol(argv[4], NULL, 16);
	printf("CMD : %s\n", argv[1]);
	printf("PPID: %d\n", getpid());
	printf("Restore file: %d\n", filePid); 

	//fds.path = "/dump/hello";
	//fds.fd = 3;

	pid = restore_fork(filePid, filepath);
	insert_breakpoint(pid, filepath);
	remap_vm(pid, stack_addr, stack_size, &orig);
			waitpro(pid, &status);
			//printf("sig stopped: %d\n", WSTOPSIG(status));
					setmems(pid, filePid, stack_addr);
					setregs(pid, filePid);
					ptrace_cont(pid);
			waitpro(pid, &status);
			print_regs(pid);

		while(1){}
	return 0;
}

