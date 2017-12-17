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

#define BUFSIZE 1024
#define PATHBUF 30

int target(char *path, char* argv[]);
Elf64_Addr get_entry_point(char* filepath);

void prepare_change_stack(int pid, unsigned long int old_addr,
	        unsigned long int old_size, struct orig *orig){
	inject_syscall(pid, orig, NULL, SYSCALL_ARGS,
		       	11, old_addr, old_size, 0x0, 0x0, 0x0, 0x0);
}

unsigned long int change_stack(int pid, unsigned long int new_addr,
	       	unsigned long int new_size, struct orig *orig){
	restore_orig(pid, orig);
	inject_syscall(pid, orig, NULL, SYSCALL_ARGS,
		       	9, new_addr, new_size, PROT_READ | PROT_WRITE,
		       	MAP_PRIVATE | LINUX_MAP_ANONYMOUS, 0x0, 0x0);
	return new_addr;
}

unsigned long int prepare_restore_files(int pid, char *path, struct orig *orig){
	printf("PATH:%s\n", path);
	restore_orig(pid, orig);
	inject_syscall(pid, orig, path, SYSCALL_ARGS, 2, (unsigned long int)path, O_RDWR, 0x0, 0x0, 0x0, 0x0);
}

int main(int argc, char* argv[]){
	int pid, filePid;
	int status;
	int flag = 0;
	char *filepath;
	long origin_text;
	Elf64_Addr entry_point;
	unsigned long int stack_addr;
	unsigned long int stack_size;
	int file_offset;
	struct orig orig;
	char *restore_path = "/dump/hello";

	if(argc < 5){
		printf("Usage: %s <path> <file pid> <stack addr> <file offset>\n", argv[0]);
		exit(1);
	}

	filepath = argv[1];
	filePid = atoi(argv[2]);
	//stack_addr = 0x7ffffffdf000;
	stack_addr = strtol(argv[3], NULL, 16);
	stack_size = 0x20000;
	if(stack_addr != 0x7ffffffdf000){
		stack_size = 0x21000;
	}
	file_offset = atoi(argv[4]);
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
					if(flag == 1){
					 	setregs(pid, filePid);
						printf("finished setting registers\n");
						prepare_change_stack(pid, 0x7ffffffdf000, 0x20000, &orig);
						printf("prepare changed stack position in memory layout\n");
					}else if(flag == 2){
						change_stack(pid, stack_addr, stack_size, &orig);

						printf("changed stack position in memory layout\n");
						printf("stack_addr %lx\n", stack_addr);
					}else if(flag == 3){
						prepare_restore_files(pid, restore_path, &orig);
					}else if(flag == 4){
						restore_orig(pid, &orig);
						inject_syscall(pid, &orig, NULL, SYSCALL_ARGS, 8, 0x3, file_offset, SEEK_SET, 0x0, 0x0, 0x0);
					}else if(flag == 5){
						restore_orig(pid, &orig);
						setmems(pid, filePid, stack_addr);
					}
					else{
						print_regs(pid);
					}
					if(flag < 6)
						ptrace_cont(pid);
					else{
						ptrace_step(pid);
						sleep(1);
					}
					flag++;
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
