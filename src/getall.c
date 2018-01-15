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

#include <time.h>

#define BUFSIZE 1024
#define PATHBUF 30

int tracing(pid_t pid);


int main(int argc, char* argv[]){
	pid_t pid;
	struct timespec begin, end;
	if(argc < 2){
		printf("Usage: %s <pid to be traced>\n", argv[0]);
		exit (1);
	}
	pid = atoi(argv[1]);
	clock_gettime(CLOCK_MONOTONIC, &begin);
	tracing(pid);
	clock_gettime(CLOCK_MONOTONIC, &end);
	if(end.tv_nsec < begin.tv_nsec){
		printf("time0.%09ld\n", 1000000000 + (end.tv_nsec - begin.tv_nsec));
	}else

	printf("time%ld.%09ld\n", (end.tv_sec - begin.tv_sec), (end.tv_nsec - begin.tv_nsec));
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

