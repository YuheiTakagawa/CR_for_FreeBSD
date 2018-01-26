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
	struct timespec begin, end;
	pid_t pid;
	if(argc < 2){
		printf("Usage: %s <pid to be traced>\n", argv[0]);
		exit (1);
	}
	pid = atoi(argv[1]);
	clock_gettime(CLOCK_MONOTONIC, &begin);
	tracing(pid);
	clock_gettime(CLOCK_MONOTONIC, &end);
	if(end.tv_nsec < begin.tv_nsec){
		printf("alltime0.%09ld\n", 1000000000 + (end.tv_nsec - begin.tv_nsec));
	}else

	printf("alltime%ld.%09ld\n", (end.tv_sec - begin.tv_sec), (end.tv_nsec - begin.tv_nsec));
}

int tracing(pid_t pid){
	struct timespec begin, end;
	int status;
	
	ptrace_attach(pid);

	waitpro(pid, &status);

	if(WIFEXITED(status)){
	} else if (WIFSTOPPED(status)){
		printf("stop %d\n", pid);
	clock_gettime(CLOCK_MONOTONIC, &begin);
		getfd(pid);
	clock_gettime(CLOCK_MONOTONIC, &end);
	if(end.tv_nsec < begin.tv_nsec){
		printf("fdstime0.%09ld\n", 1000000000 + (end.tv_nsec - begin.tv_nsec));
	}else

	printf("fdstime%ld.%09ld\n", (end.tv_sec - begin.tv_sec), (end.tv_nsec - begin.tv_nsec));
	clock_gettime(CLOCK_MONOTONIC, &begin);
		getregs(pid);
	clock_gettime(CLOCK_MONOTONIC, &end);
	if(end.tv_nsec < begin.tv_nsec){
		printf("regtime0.%09ld\n", 1000000000 + (end.tv_nsec - begin.tv_nsec));
	}else

	printf("regtime%ld.%09ld\n", (end.tv_sec - begin.tv_sec), (end.tv_nsec - begin.tv_nsec));
	clock_gettime(CLOCK_MONOTONIC, &begin);
		getmems(pid);
	clock_gettime(CLOCK_MONOTONIC, &end);
	if(end.tv_nsec < begin.tv_nsec){
		printf("memtime0.%09ld\n", 1000000000 + (end.tv_nsec - begin.tv_nsec));
	}else

	printf("memtime%ld.%09ld\n", (end.tv_sec - begin.tv_sec), (end.tv_nsec - begin.tv_nsec));
	}
	printf("Checkpoint\n");
	ptrace_detach(pid);

	return 0;
}

