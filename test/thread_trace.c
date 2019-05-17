#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

void __print_regs(struct reg *reg){
	printf("RAX: %lx excuted\n", reg->r_rax);
        printf("RBX: %lx excuted\n", reg->r_rbx);
        printf("RCX: %lx excuted\n", reg->r_rcx);
        printf("RDX: %lx excuted\n", reg->r_rdx);
        printf("RSI: %lx excuted\n", reg->r_rsi);
        printf("RDI: %lx excuted\n", reg->r_rdi);
        printf("RBP: %lx excuted\n", reg->r_rbp);
        printf("RSP: %lx excuted\n", reg->r_rsp);
        printf("RIP: %lx excuted\n", reg->r_rip);
        printf("FLG: %lx excuted\n", reg->r_rflags);
        printf("R8 : %lx excuted\n", reg->r_r8);
        printf("R9 : %lx excuted\n", reg->r_r9);
        printf("R10: %lx excuted\n", reg->r_r10);
        printf("R11: %lx excuted\n", reg->r_r11);
        printf("R12: %lx excuted\n", reg->r_r12);
        printf("R13: %lx excuted\n", reg->r_r13);
        printf("R14: %lx excuted\n", reg->r_r14);
        printf("R15: %lx excuted\n", reg->r_r15);
        printf("TRA: %x excuted\n", reg->r_trapno);
        printf("CS : %lx excuted\n", reg->r_cs);
        printf("SS : %lx excuted\n", reg->r_ss);
        printf("DS : %x excuted\n", reg->r_ds);
        printf("ES : %x excuted\n", reg->r_es);
        printf("FS : %x excuted\n", reg->r_fs);
        printf("GS : %x excuted\n", reg->r_gs);
}


int main(int argc, void *argv[]){
	int rc;
	int status;
	if (argc < 1) {
		printf("less argument\n");
		return 1;
	}

	pid_t pid = atoi(argv[1]);
	struct reg reg;
	int num;
	printf("pid: %d\n", pid);
	rc = ptrace(PT_ATTACH, pid, (caddr_t)1, 0);
	if (rc < 0){
		perror("ptrace attach");
		return 1;
	}
	if (waitpid(pid, &status, 0) < 0){
		perror("waitpid");
		return 1;
	}
	if (WIFSTOPPED(status)){
		printf("stop %d\n", pid);
		rc = ptrace(PT_GETNUMLWPS, pid, (caddr_t)&num, 0);
		printf("num %d\n", num);
		lwpid_t list[num/sizeof(lwpid_t)];
		rc = ptrace(PT_GETLWPLIST, pid, (caddr_t)&list, num);
		for(int i=0; i < num/sizeof(lwpid_t); i++){
			printf("LWP tid:%d\n", list[i]);
			rc = ptrace(PT_GETREGS, list[i], (caddr_t)&reg, 0);
			if (rc < 0){
				perror("ptrace getregs");
				return 1;
			}
			__print_regs(&reg);
		}
		printf("process =======\n");
		rc = ptrace(PT_GETREGS, pid, (caddr_t)&reg, 0);
		__print_regs(&reg);
	}


	ptrace(PT_DETACH, pid, (caddr_t)1, 0);
	return 0;
}
