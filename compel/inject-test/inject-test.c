#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

#include "parasite_syscall.h"
#include "ptrace.h"
#include "register.c"
#include "parasite-head.h"
#include "parasite.h"
#include "infect.h"
#include "rpc-pie-priv.h"
#include "infect-rpc.h"
#include "infect-priv.h"

#define LINUX_MAP_ANONYMOUS 0x20 //ANONYMOUS of FreeBSD is 0x200, ANONYMOUS of Linux is 0x20
#define PROT_ALL (PROT_EXEC | PROT_WRITE | PROT_READ) 
#define PARASITE_STACK_SIZE     (16 << 10)
#define RESTORE_STACK_SIGFRAME 0 // TODO Calc SIGFRAMESIZE
#define SHARED_FILE_PATH "/tmp/shm"

extern int injection(int);

int main(int argc, char *argv[]){

	if(argc < 2){
		printf("usage: ./inject-test <PID>\n");
		exit(1);
	}

	int pid;
	int status;
	pid = atoi(argv[1]);
	ptrace_attach(pid);
	waitpro(pid, &status);

	injection(pid);

	//ptrace_cont(pid);
	//while(1){}
	ptrace_detach(pid);
	
	return 0;
}
