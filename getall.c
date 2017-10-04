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
#include "getcpu.c"

#define BUFSIZE 1024
#define PATHBUF 30

int tracing(pid_t pid, long int daoffset, long int stoffset);


int main(int argc, char* argv[]){
	int fd;
	pid_t pid;
	long int da, st;
	if(argc < 4){
		printf("Usage: %s <pid to be traced> <Data address> <Stack address>\n", argv[0]);
		exit (1);
	}
	pid = atoi(argv[1]);

	da = strtol(argv[2], NULL, 16);
	st = strtol(argv[3], NULL, 16);

	tracing(pid, da, st);
}

int tracing(pid_t pid, long int daoffset, long int stoffset){
	int status;
	int rc;
	
	rc = ptrace(PT_ATTACH, pid, NULL, 0);
	if(rc < 0){
		perror("ptrace");
		exit (1);
	}

	waitpid(pid, &status, 0);

	if(WIFEXITED(status)){
	} else if (WIFSTOPPED(status)){
		printf("stop %d\n", pid);
		getregs(pid);
		getmems(pid, daoffset, stoffset);
	}

	ptrace(PT_DETACH, pid, (caddr_t)1, 0);
	printf("Process detached\n");
	return 0;
}

