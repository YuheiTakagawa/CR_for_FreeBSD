#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdlib.h>

#define BUFSIZE 1024
#define PATHBUF 30

char code[] = {"\x0f\x05\xCC"};

struct reg parasite_setregs(int pid, char* mem){
	struct reg reg, orig;
	char *path = "/tmp.log";
	printf("================================\n");
	ptrace(PT_GETREGS, pid, (caddr_t)&orig, 1);
	reg = orig;
	printf("Evacuation registers: %p\n", orig);

	printf("ori:%lx, reg:%lx\n", orig.r_rax, reg.r_rax);
	printf("%p\n", path);

	reg.r_rax = 5;
	reg.r_rdi = (unsigned long int)path;
	reg.r_rdx = 0x40;
	reg.r_rip = (unsigned long int)mem;
	
	ptrace(PT_SETREGS, pid, (caddr_t)&reg, 1);

	return orig;
}

void restore_setregs(int pid, struct reg orig){
	struct reg reg;
	
	ptrace(PT_GETREGS, pid, (caddr_t)&reg, 1);
	printf("return value(rax) : %lx\n", reg.r_rax);
	ptrace(PT_SETREGS, pid, (caddr_t)&orig, 1);
	printf("restore_registers\n");
}

int main(int argc, char* argv[]){
	int pid;
	int status;
	int flag = 0;
	
	char *mem;
	pid = atoi(argv[1]);

	ptrace(PT_ATTACH, pid, NULL, 0);
	printf("Attached\n");

	waitpid(pid, &status, 0);

	if(WIFEXITED(status)){
	}else if (WIFSTOPPED(status)){
		printf("stop pid = %d, by signal = %d\n", pid, status);

	mem = (char*) mmap(NULL, 1024, PROT_WRITE|PROT_READ|PROT_EXEC, MAP_ANONYMOUS |MAP_PRIVATE, -1, 0);
	if(mem == MAP_FAILED){
		perror("mmap");
		exit(1);
	}
	printf("add mem: %p\n", mem);
	struct reg orig;
	orig = parasite_setregs(pid, mem);
	restore_setregs(pid, orig);

	}

	return 0;
}
