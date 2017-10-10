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
int setmems(pid_t pid, pid_t filePid);
int write_mem(int read_fd, int write_fd, long int offset);
int setregs(pid_t pid, pid_t filePid);
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
				if(flag == 0){
					ptrace(PT_WRITE_I, pid, (caddr_t)0x400470, 0xCC);
					ptrace(PT_CONTINUE, pid, (caddr_t)1, 0);
					flag++;
				}
				else{
					printf("stopped:%d\n", WSTOPSIG(status));
					setmems(pid, filePid);
					setregs(pid, filePid);
					printf("finished setting values\n");
					ptrace(PT_DETACH, pid, (caddr_t)1, 0);
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
	ptrace(PT_TRACE_ME, 0, NULL, 0);
	printf("trace me\n");
	
	ret = execvp(exec[0], exec);
	perror("execvp");
	exit(ret);
}

int setregs(int pid, pid_t filePid){
	struct reg reg;
	int fd;

	memset(&reg, 0, sizeof(reg));
	fd = open_file(filePid, "regs");
	read(fd, &reg, sizeof(reg));
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
