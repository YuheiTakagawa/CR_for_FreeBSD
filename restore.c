#include <stdio.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>

#include "register.c"
#include "setmem.c"
#include "ptrace.h"
#define BUFSIZE 1024
#define PATHBUF 30

int target(char *path, char* argv[]);
Elf64_Addr get_entry_point(char* filepath);


int main(int argc, char* argv[]){
	int pid, filePid;
	int status;
	int flag = 0;
	char *filepath;
	long origin_text;
	Elf64_Addr entry_point;

	if(argc < 3){
		printf("Usage: %s <path> <file pid>\n", argv[0]);
		exit(1);
	}

	filepath = argv[1];
	filePid = atoi(argv[2]);
	printf("CMD : %s\n", argv[1]);
	printf("PPID: %d\n", getpid());
	printf("Restore file: %d\n", filePid); 

	pid = fork();
	if(pid < 0){
		perror("FORK");
		exit(1);
	}
	
	if(pid == 0){
		target(filepath, NULL);
	}else{
		while(1){
			waitpro(pid, &status);
			if(WIFSTOPPED(status)){
				if(flag == 0){
				//	entry_point = get_entry_point(filepath);
					entry_point = 0x4009ae;
					origin_text = ptrace_read_i(pid, entry_point);
					ptrace_write_i(pid, entry_point, 0xCC);
					ptrace_cont(pid);
					flag++;
				}
				else{
					printf("stopped:%d\n", WSTOPSIG(status));
					setmems(pid, filePid);
					ptrace_write_i(pid, entry_point, origin_text);
					setregs(pid, filePid);
					printf("finished setting values\n");
					ptrace_cont(pid);
				}
			}else if(WIFEXITED(status)){
				perror("exited");
				exit(1);
			}
		}
	}
	return 0;
}

int target(char *path, char *argv[]){
	char *exec[] = {path, NULL};
	int ret;
	printf("CPID: %d\n", getpid());
	printf("command: %s\n", exec[0]);
	ptrace_traceme();
	printf("trace me\n");
	
	ret = execvp(exec[0], exec);
	perror("execvp");
	exit(ret);
}

Elf64_Addr get_entry_point(char* filepath){
		Elf64_Ehdr header;
		int fd = open(filepath, O_RDONLY);
		memset(&header, 0, sizeof(Elf64_Ehdr));

		read(fd, &header, sizeof(header));
		Elf64_Addr entry = header.e_entry;
		return entry;
}
