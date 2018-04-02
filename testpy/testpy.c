#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/mman.h>

#include "ptrace.h"
#include "parasite_syscall.h"
#include "parasite-head.h"

#define PARASITE_STACK_SIZE (16 << 10)

void inject_syscall_buf(int pid, char *buf, void *addr, int size){
        int *tmp = malloc(sizeof(int));
        if(size == 0){
                size = strlen(buf);
        }
        for(int i = 0; i < size /4 + 1; i++){
                memset(tmp, 0, 4 + 1);
                memcpy(tmp, buf + i * 4, 4);
                ptrace_write_i(pid, (unsigned long int)addr + i * 4, *tmp);
        }
        free(tmp);
}


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
	long int map, remote_map;
	char hello[] = "/tmp/shm";
	struct reg reg; 
	ptrace_attach(pid);
	waitpro(pid, &status);
	printf("Attach\n");

	compel_syscall(pid, &orig,
			477, &map, 0x7fffffede000, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON, -1, 0x0);

	inject_syscall_buf(pid, hello, (void *)map, sizeof(hello));
	compel_syscall(pid, &orig,
			0x5, &ret, map, O_RDWR, 0x0, 0x0, 0x0, 0x0);
	printf("remote_fd: %ld\n", ret);
	compel_syscall(pid, &orig,
			477, &remote_map, 0x0, 0x1000, PROT_WRITE| PROT_READ|PROT_EXEC, MAP_SHARED | MAP_FILE, ret, 0x0);

	int fd = open("/tmp/shm", O_RDWR);
	void *local_map = mmap(0x0, sizeof(parasite_blob), PROT_WRITE|PROT_READ|PROT_EXEC, MAP_SHARED, fd, 0);
	memcpy(local_map, parasite_blob, sizeof(parasite_blob));

	ptrace_get_regs(pid, &reg);
	reg.r_rip = (unsigned long int) remote_map;
	reg.r_rbp = (unsigned long int) remote_map + sizeof(parasite_blob);

	reg.r_rbp += PARASITE_STACK_SIZE;

	ptrace_set_regs(pid, &reg);
	ptrace_cont(pid);

	waitpro(pid, &status);
	ptrace_set_regs(pid, &orig.reg);
	
	ptrace_detach(pid);
//	waitpro(pid, status);
	
}
