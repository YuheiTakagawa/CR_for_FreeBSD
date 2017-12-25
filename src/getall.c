#define _WITH_DPRINTF
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <string.h>
#include <stdlib.h>

#include "getmem.c"
#include "register.c"
#include "getfd.c"

#define BUFSIZE 1024
#define PATHBUF 30

int tracing(pid_t pid);


int main(int argc, char* argv[]){
	pid_t pid;
	if(argc < 2){
		printf("Usage: %s <pid to be traced>\n", argv[0]);
		exit (1);
	}
	pid = atoi(argv[1]);

	tracing(pid);
}

int tracing(pid_t pid){
	int status;
	
	ptrace_attach(pid);

	waitpro(pid, &status);

	if(WIFEXITED(status)){
	} else if (WIFSTOPPED(status)){
		printf("stop %d\n", pid);
		getfd(pid);
		getregs(pid);
		getmems(pid);
	}
	printf("Checkpoint\n");
	ptrace_detach(pid);

	return 0;
}

