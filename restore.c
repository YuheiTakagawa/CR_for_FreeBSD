#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#define BUFSIZE 1024
#define PATHBUF 30

int target(char *path, char* argv[]);
int setmems(pid_t pid, int filePid);
int write_mem(int read_fd, int write_fd, long int offset);
int setregs(pid_t pid);
int open_file(pid_t pid, char* st);


int main(int argc, char* argv[]){
	int pid, filePid;
	int status;
	int flag = 0;
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
			if(waitpid(pid, &status, 0) < 0){
				perror("waitpid");
				exit(1);
			}
			if(WIFSTOPPED(status)){
				printf("stopped:%d\n", WSTOPSIG(status));
				setmems(pid, filePid);
				setregs(pid);
				ptrace(PT_DETACH, pid, (caddr_t)1, 0);
				printf("finished setting values\n");
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
	ptrace(PT_TRACE_ME, 0, NULL, 0);
	printf("trace me\n");
	
	ret = execvp(exec[0], exec);
	perror("execvp");
	exit(ret);
}

int setregs(int pid){
	struct reg reg;

	reg.r_rax = 0x4;
	reg.r_rbx = 0x1;
	reg.r_rcx = 0xb6732c493a81f428;
	reg.r_rdx = 0xa;
	reg.r_rsi = 0x7fffffffea80;
	reg.r_rdi = 0x7fffffffea90;
	reg.r_rbp = 0x7fffffffead0;
	reg.r_rsp = 0x7fffffffea78;
	reg.r_rip = 0x40b7aa;
	reg.r_rflags = 0x203;
	reg.r_r8 = 0x7fffffbac830;
	reg.r_r9 = 0xf;
	reg.r_r10 = 0x0;
	reg.r_r11 = 0x7fffffffe958;
	reg.r_r12 = 0x2;
	reg.r_r13 = 0x7fffffffeb68;
	reg.r_r14 = 0x7fffffffeb58;
	reg.r_r15 = 0x1;
	reg.r_cs = 0x43;
	reg.r_ss = 0x3b;
	reg.r_ds = 0x3b;
	reg.r_es = 0x3b;
	reg.r_fs = 0x13;
	reg.r_gs = 0x1b;
	if(ptrace(PT_SETREGS, pid, (caddr_t)&reg, 0) < 0){
		perror("ptrace(PT_SETREGS, ...)");
		exit(1);
	}
	return 0;
}

int setmems(pid_t pid, pid_t filePid){
	int write_fd;
	int read_fd;
	char buf[BUFSIZE];

	write_fd = open_file(pid, "mem");
	

	read_fd = open_file(filePid, "data");
	write_mem(read_fd, write_fd, 0x665000);	

	read_fd = open_file(filePid, "stack");
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
