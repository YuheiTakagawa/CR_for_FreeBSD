#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>

#include "ptrace.h"
#include "parasite_syscall.h"

int main(int argc, char *argv[]){
	if(argc < 2){
		printf("usage: ./test <PID>\n");
		exit(1);
	}

	pid_t pid = atoi(argv[1]);
	printf("PID: %d\n", pid);
	int status;
	struct orig orig;
	long int ret;
	long int map;
	char hello[] = "HELLO TAKA\n";
	ptrace_attach(pid);
	waitpro(pid, &status);
	printf("Attach\n");

	compel_syscall(pid, &orig,
			477, &map, 0x7fffffede000, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON, -1, 0x0);
	for(int i = 0; i < sizeof(hello); i++){
		ptrace_write_i(pid, map + i, hello[i]);
	}
	compel_syscall(pid, &orig,
			4, &ret, 1, map, sizeof(hello), 0x0, 0x0, 0x0);
	ptrace_detach(pid);
//	waitpro(pid, status);
	
}
