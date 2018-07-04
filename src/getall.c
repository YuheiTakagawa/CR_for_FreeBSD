#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "common.h"
#include "getmem.h"
#include "fds.h"
#include "parasite_syscall.h"
#include "ptrace.h"
#include "register.h"

int tracing(pid_t pid, int *options);
extern int injection(pid_t pid, int *options);


/*
int main(int argc, char* argv[]){
	pid_t pid;
	if(argc < 2){
		printf("Usage: %s <pid to be traced>\n", argv[0]);
		exit (1);
	}
	pid = atoi(argv[1]);

	tracing(pid);
}
*/

int tracing(pid_t pid, int *options){
	int status;
	
	ptrace_attach(pid);

	waitpro(pid, &status);

	if(WIFSTOPPED(status)){
		printf("stop %d\n", pid);
		getfd(pid);
		getregs(pid);
		getmems(pid);
		injection(pid, options);
		//while(1){}
	}
	printf("Checkpoint\n");
	ptrace_detach(pid);
	kill(pid, 9);

	return 0;
}

