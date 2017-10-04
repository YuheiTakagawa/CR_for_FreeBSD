#include <assert.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char* argv[]){
	int status;
	int rc;
	int count = 0;
	pid_t pid;
	if(argc < 2){
		printf("Usage: %s <pid to be traced>\n", argv[0]);
		exit (1);
	}
	pid = atoi(argv[1]);

	struct reg reg;
	long ins = 0;
	memset(&reg, 0, sizeof(reg));
	printf("Attaching to %ld\n", pid);
	rc = ptrace(PT_ATTACH, pid, NULL, 0);
	if(rc < 0){
		perror("ptrace");
		exit (1);
	}

	while(1){
		waitpid(pid, &status, 0);
		printf("%d\n", count);
		if(WIFEXITED(status)){
			break;
		} else if (WIFSTOPPED(status)){
			printf("stop %d\n", WSTOPSIG(status));
			rc = ptrace(PT_GETREGS, pid, (caddr_t)&reg, 0);
			if((int)reg.r_rax==0xf0)
				reg.r_rbx = reg.r_rbx+10;
			rc = ptrace(PT_SETREGS, pid, (caddr_t)&reg, 0);
			rc = ptrace(PT_GETREGS, pid, (caddr_t)&reg, 0);
			if(rc < 0){
				perror("ptrace");
				exit (1);
			}
			//rc = ptrace(PT_READ_D, pid, (void *)ins, 0);
			printf("RAX: %lx excuted\n", reg.r_rax);
			printf("RBX: %lx excuted\n", reg.r_rbx);
			printf("RCX: %lx excuted\n", reg.r_rcx);
			printf("RDX: %lx excuted\n", reg.r_rdx);
			printf("RSI: %lx excuted\n", reg.r_rsi);
			printf("RDI: %lx excuted\n", reg.r_rdi);
			printf("RBP: %lx excuted\n", reg.r_rbp);
			printf("R8 : %lx excuted\n", reg.r_r8);
			printf("R9 : %lx excuted\n", reg.r_r9);
			printf("R10: %lx excuted\n", reg.r_r10);
			printf("R11: %lx excuted\n", reg.r_r11);
			printf("R12: %lx excuted\n", reg.r_r12);
			printf("R13: %lx excuted\n", reg.r_r13);
			printf("R14: %lx excuted\n", reg.r_r14);
			printf("R15: %lx excuted\n", reg.r_r15);
		}
		//reg.r_r9 = 0xa;
		//rc = ptrace(PT_SETREGS, pid, (caddr_t)&reg, 0);
		//ptrace(PT_CONTINUE, pid, (caddr_t)1, 0);
		ptrace(PT_SYSCALL, pid, (caddr_t)1 , 0);
		printf("process cotinue\n");
		count++;
	}

	ptrace(PT_DETACH, pid, (caddr_t)1, 0);
	printf("Process detached\n");
	return 0;
}
