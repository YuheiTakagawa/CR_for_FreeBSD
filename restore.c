#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

int target(char *path, char* argv[]);
int getregs(int pid);

int main(int argc, char* argv[]){
	int pid;
	int status;
	char *path;
	if(argc < 2){
		printf("Usage: %s path\n", argv[0]);
		exit(1);
	}
	printf("%s\n", argv[1]);
	printf("PPID: %d\n", getpid());

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
				printf("stopped\n");
				getregs(pid);
				ptrace(PT_CONTINUE, pid, (caddr_t)1, 0);
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


int getregs(int pid){
	struct reg reg;
	ptrace(PT_GETREGS, pid, (caddr_t)&reg, 0);

	printf("RAX: %lx \n", reg.r_rax);
	printf("RBX: %lx \n", reg.r_rbx);
	printf("RCX: %lx \n", reg.r_rcx);
	printf("RDX: %lx \n", reg.r_rdx);

	return 0;
}
