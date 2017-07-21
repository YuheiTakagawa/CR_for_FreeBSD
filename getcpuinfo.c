#include <stdio.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char* argv[]){
	int status;
	int rc;
	pid_t pid;
	if(argc < 2){
		printf("Usage: %s <pid to be traced>\n", argv[0]);
		exit (1);
	}
	pid = atoi(argv[1]);

	printf("Attaching to %ld\n", pid);
	rc = ptrace(PT_ATTACH, pid, NULL, 0);
	if(rc < 0){
		perror("ptrace");
		exit (1);
	}
	waitpid(pid, &status, 0);

	struct reg reg;
	long ins=0;

	memset(&reg, 0, sizeof(reg));
	
	rc = ptrace(PT_GETREGS, pid, (caddr_t)&reg, 0);
	if(rc < 0){
		perror("ptrace");
		exit (1);
	}
	//rc = ptrace(PT_READ_D, pid, (void *)ins, 0);
	ptrace(PT_DETACH, pid, NULL, 0);
	printf("RAX: %lx excuted\n", reg.r_rax);
	printf("RBX: %lx excuted\n", reg.r_rbx);
	printf("RCX: %lx excuted\n", reg.r_rcx);
	printf("RDX: %lx excuted\n", reg.r_rdx);
	printf("RSI: %lx excuted\n", reg.r_rsi);
	printf("RDI: %lx excuted\n", reg.r_rdi);
	printf("RBP: %lx excuted\n", reg.r_rbp);
	printf("R8: %lx excuted\n", reg.r_r8);
	printf("R9: %lx excuted\n", reg.r_r9);
	printf("Process detached\n");
	return 0;
}

