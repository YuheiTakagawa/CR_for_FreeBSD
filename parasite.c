#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>

#define BUFSIZE 1024
#define PATHBUF 30

long code = 0xcc050f;

struct orig{
	long text;
	long data;
	char *addr;
	struct reg reg;
};

struct orig *parasite_setregs(int pid, char* mem, struct orig *orig){
	struct reg reg;
	char *path = "Inject!\n";

	printf("================================\n");
	ptrace(PT_GETREGS, pid, (caddr_t)&reg, 1);
	printf("Get registers: \n");
	orig->reg = reg;
	printf("Evacuation registers: \n");

	printf("path: %p\n", path);

/* completed write system call injection */
	
	reg.r_rax = 1;
	reg.r_rdi = 1;
	reg.r_rsi = (unsigned long int)path; 
	reg.r_rdx = sizeof(path);
	reg.r_r10 = 0x0;	
	reg.r_r8  = 0x0;
	reg.r_r9  = 0x0;
	
	printf("path:%s, rdi:%d, size:%d\n", path, reg.r_rdi, reg.r_r10);
	printf("rip:%lx\n", reg.r_rip);
/* changed memory direct */
	/* get origal memory */
	orig->text = ptrace(PT_READ_I, pid, (caddr_t)reg.r_rip, 0);
	orig->data = ptrace(PT_READ_D, pid, (caddr_t)path, 0);
	orig->addr = path;
	/******************************/

	/* injection syscall 0xcc050f */	
	if(ptrace(PT_WRITE_I, pid, (caddr_t)reg.r_rip, code) < 0){
		perror("ptrace(WRITE_I)");
		exit(1);
	}
	/******************************/

 	int* tmp = malloc(sizeof(int));
/*
	memset(tmp, 0, 4 + 1);
 	memcpy(tmp, code, 4);
 	if(ptrace(PT_WRITE_I, pid, (caddr_t)reg.r_rip, *tmp) < 0){
 		perror("ptrace(WRITE_I)");
 		exit(1);
 	}
*/
	/* write buffer convert to machine lang*/
	for(int i = 0; i < strlen(path) / 4 + 1; i++){
		memset(tmp, 0, 4 + 1);
		memcpy(tmp, path + i * 4, 4);
		if(ptrace(PT_WRITE_D, pid, (caddr_t)path + i*4 , *tmp) < 0){
			perror("ptrace(WRITE_I)");
			exit(1);
		}
	}

	free(tmp);

	printf("orig_text: %lx\n", orig->text);
	printf("orig_data: %lx\n", orig->data);
	
/************************/
	
	if(ptrace(PT_SETREGS, pid, (caddr_t)&reg, 1) < 0){
		perror("ptrace(SETREGS)");
		exit(1);
	}

	return orig;
}

void restore_setregs(int pid, struct reg orig){
	struct reg reg;
	
	ptrace(PT_GETREGS, pid, (caddr_t)&reg, 1);
	printf("return value(rax) : %lx\n", reg.r_rax);
	ptrace(PT_SETREGS, pid, (caddr_t)&orig, 1);
	printf("restore_registers\n");
}

void restore_memory(int pid, struct orig *orig){
	ptrace(PT_WRITE_I, pid, (caddr_t)orig->reg.r_rip, orig->text);
	ptrace(PT_WRITE_I, pid, (caddr_t)orig->addr, orig->data);
	
}
int main(int argc, char* argv[]){
	int pid;
	int status;
	int flag = 0;
	
	char *mem;
	struct orig orig;
	pid = atoi(argv[1]);

	if(ptrace(PT_ATTACH, pid, NULL, 0) < 0){
		perror("ptrace(ATTACH)");
		exit(1);
	}
	printf("Attached PID:%d\n", pid);

	if(waitpid(pid, &status, 0) < 0){
		perror("waitpid");
		exit(1);
	}

	if(WIFEXITED(status)){
	}else if (WIFSTOPPED(status)){
		printf("stop PID = %d, by signal = %d\n", pid, WSTOPSIG(status));

		mem = (char*) mmap(NULL, 1024, PROT_WRITE|PROT_READ|PROT_EXEC, MAP_ANONYMOUS |MAP_PRIVATE, -1, 0);
		if(mem == MAP_FAILED){
			perror("mmap");
			exit(1);
		}
		printf("add mem: %p\n", mem);
		parasite_setregs(pid, mem, &orig);
		ptrace(PT_CONTINUE, pid, (caddr_t)1, 0);
	}
	if(waitpid(pid, &status, 0) < 0){
		perror("waitpid");
		exit(1);
	}

	if(WIFEXITED(status)){
	}else if(WIFSTOPPED(status)){
		printf("stop PID = %d, by signal = %d\n", pid, WSTOPSIG(status));

		restore_setregs(pid, orig.reg);
		restore_memory(pid, &orig);
		ptrace(PT_DETACH, pid, (caddr_t)1, 0);
	}

	return 0;
}
