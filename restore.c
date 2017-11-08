#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/user.h>
#include <sys/reg.h>

#define BUFSIZE 1024
#define PATHBUF 30

int target(char *path, char* argv[]);
int setmems(pid_t pid, pid_t filePid);
int write_mem(int read_fd, int write_fd, long int offset);
int setregs(pid_t pid, pid_t filePid);
int open_file(pid_t pid, char* st);


int main(int argc, char* argv[]){
	int pid, filePid;
	int status;
	int flag = 0;
	long origin;
	if(argc < 3){
		printf("Usage: %s <path> <file pid>\n", argv[0]);
		exit(1);
	}
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
		target(argv[1],NULL);
	}else{
		while(1){
			printf("wait pid:%d\n", pid);
			if(waitpid(pid, &status, 0) < 0){
				perror("waitpid");
				exit(1);
			}
			if(WIFSTOPPED(status)){
				if(flag == 0){
					origin = ptrace(PTRACE_PEEKTEXT, pid, 0x4009ae, 0);
					ptrace(PTRACE_POKETEXT, pid, 0x4009ae, 0xCC);
					if(ptrace(PTRACE_CONT, pid, NULL, NULL) < 0){
	perror("ptrace_cont");
	exit(1);
}
					flag++;
				}else if(flag <10){
					ptrace(PTRACE_POKETEXT, pid, 0x4009ae, origin);
					ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
					flag++;
				}
				else if (flag == 10){
					printf("stopped:%d\n", WSTOPSIG(status));
					setmems(pid, filePid);
					setregs(pid, filePid);
					printf("finished setting values\n");
					ptrace(PTRACE_CONT, pid, NULL, NULL);
					flag++;
//sleep(1);
				}else{
					struct user_regs_struct reg1;
					ptrace(PTRACE_GETREGS, pid, NULL, reg1);
					printf("RAX:%llx\n", reg1.rax);
					printf("OAX:%llx\n", reg1.orig_rax);
					printf("RIP:%llx\n", reg1.rip); 
					ptrace(PTRACE_CONT, pid, NULL, NULL);
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
	ptrace(PTRACE_TRACEME, 0, NULL, 0);
	printf("trace me\n");
	ret = execvp(exec[0], exec);
	perror("execvp");
	exit(ret);
}

int setregs(int pid, pid_t filePid){
	struct user_regs_struct reg;
	int fd;

	memset(&reg, 0, sizeof(reg));
	fd = open_file(filePid, "regs");
//	read(fd, &reg, sizeof(reg));
	reg.orig_rax = 0x1;
	reg.rax      = 0x1;
	reg.rbx	     = 0x4002c8;
	reg.rcx	     = 0x64;
	reg.rdx      = 0x32;
	reg.rsi      = 0x7fffffffdb10;
	reg.rdi      = 0x1;
	reg.rbp      = 0x7fffffffdb50;
	reg.rsp      = 0x7fffffffdae8;
	reg.rip      = 0x43f5e0;
	reg.eflags   = 0x246;
	reg.fs_base  = 0x6dc880;
	reg.gs_base  = 0x0;
	reg.r8       = 0x0;
	reg.r9       = 0x9;
	reg.r10      = 0x64;
	reg.r11      = 0x1;
	reg.r12      = 0x4015c0;
	reg.r13      = 0x401650;
	reg.r14      = 0x0;
	reg.r15      = 0x0;
	reg.cs       = 0x43;
	reg.ss       = 0x3b;
	reg.ds       = 0x3b;
	reg.es       = 0x3b;
	reg.fs       = 0x13;
	reg.gs       = 0x1b;
	printf("rax:%llx\n", reg.orig_rax);
	printf("rip:%llx\n", reg.rip);
	printf("rbp:%llx\n", reg.rbp);
	if(ptrace(PTRACE_SETREGS, pid, 0, &reg) < 0){
		perror("ptrace(PTRACE_SETREGS, ...)");
	}
					struct user_regs_struct reg1;
					ptrace(PTRACE_GETREGS, pid, NULL, &reg1);
					printf("RAX:%llx\n", reg1.rax);
					printf("OAX:%llx\n", reg1.orig_rax);
					printf("RIP:%llx\n", reg1.rip); 
					printf("RBP:%llx\n", reg1.rbp); 
	return 0;
}

int setmems(pid_t pid, pid_t filePid){
	int write_fd;
	int read_fd;
	char buf[BUFSIZE];

	write_fd = open_file(pid, "mem");
	

	read_fd = open_file(filePid, "data");
	write_mem(read_fd, write_fd, 0x6c9000);	
	

//	char tmp[50], *tmp2;
	//snprintf(tmp, sizeof(tmp), "bash getstack.sh %d", pid);
	//FILE *fp = popen(tmp, "r");
//	fgets(tmp, sizeof(tmp), fp);	
//	printf("%llx\n", strtoll(tmp, &tmp2, 16));
	read_fd = open_file(filePid, "stack");
	//write_mem(read_fd, write_fd, strtoll(tmp, &tmp2, 16));
	write_mem(read_fd, write_fd, 0x7ffffffdf000);

	close(write_fd);
	return 0;
}

int open_file(pid_t pid, char* flag){
	char filepath[PATHBUF];

	if(flag == "mem"){
		snprintf(filepath, sizeof(filepath), "/proc/%d/mem", pid);
		return  open(filepath, O_WRONLY);
	}	
	snprintf(filepath, sizeof(filepath), "/dump/%d_%s.img", pid, flag);
	return open(filepath, O_RDONLY);
}

int write_mem(int read_fd, int write_fd, long int offset){
	char buf[BUFSIZE];
	int rnum;

	lseek(write_fd, offset, SEEK_SET);

	while(1){

		rnum = read(read_fd, buf, sizeof(buf));
		if(rnum > 0){
			write(write_fd, buf, rnum);
		}else{
			close(read_fd);
			break;
		}
	}
	return rnum;
}
