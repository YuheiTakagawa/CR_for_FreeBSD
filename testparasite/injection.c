#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <string.h>
#include "parasite_syscall.c"
#include "ptrace.h"
#include "register.c"
#include "parasite-head.h"

#define LINUX_MAP_ANONYMOUS 0x20

void inject_syscall_buf(int pid, char *buf, unsigned long int addr, int size){
	int *tmp = malloc(sizeof(int));
	if(size == 0){
		size = strlen(buf);
	}
	for(int i = 0; i < size /4 + 1; i++){
		memset(tmp, 0, 4 + 1);
		memcpy(tmp, buf + i * 4, 4);
	//	printf("add:%lx, tmp:%x\n", (unsigned long int)addr + i * 4, *tmp);
		ptrace_write_i(pid, (unsigned long int)addr + i * 4, *tmp);
	}
	free(tmp);
}

int main(int argc, char *argv[]){
	if(argc < 2){
		printf("usage: ./injection <PID>\n");
		exit(1);
	}
	struct orig orig;
	int status;
	int pid = atoi(argv[1]);
	ptrace_attach(pid);
	waitpro(pid, &status);
	void *remote_map, *remote_fd_map, *local_map;
	char buf[] = "/dump/XXXXX";
	int fd;
	long remote_fd;
	struct reg reg, orireg;
	long ret;
	
	remote_map = remote_mmap(pid, &orig, (void *) 0x0, 0x1000, PROT_EXEC | PROT_READ | PROT_WRITE, LINUX_MAP_ANONYMOUS | MAP_SHARED, 0x0, 0x0);
	printf("remote_map:%lx\n", (off_t)remote_map);

	fd = open(buf, O_RDWR);
	printf("open: %s, fd: %d\n", buf, fd);
	
	//ptrace_poke_area(pid, buf, (void *)buf, sizeof(buf));
	inject_syscall_buf(pid, buf, (unsigned long int)remote_map, 0);
	printf("p:%p, lx%lx\n", buf, (unsigned long int)buf);
	compel_syscall(pid, &orig, 0x2, &remote_fd, (unsigned long)remote_map, O_RDWR, 0x0, 0x0, 0x0, 0x0);
	printf("remote_fd:%ld\n", remote_fd);
	remote_fd_map = remote_mmap(pid, &orig, (void *) 0x0, 0x1000, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_SHARED | LINUX_MAP_ANONYMOUS, 0x0, 0x0);
	//remote_fd_map = remote_mmap(pid, &orig, (void *) 0x0, 0x1000, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_SHARED, remote_fd, 0x0);
	printf("remote_fd_map:%lx\n", (unsigned long int)remote_fd_map);
	
	local_map = mmap(0x0, 0x1000, PROT_EXEC | PROT_WRITE |PROT_READ, MAP_SHARED, fd, 0);
	if((int)local_map < 0){
		perror("mmap(2)");
	}
	printf("local_map:%p\n", local_map);
	inject_syscall_buf(pid, (char *)parasite_head, (unsigned long int)remote_fd_map, parasite_head_len);
	//memcpy(remote_map, writecall_o, 0x1000);
	//msync(local_map, 0x0, MS_SYNC);
	ptrace_get_regs(pid, &reg);
	memcpy(&orireg, &reg, sizeof(reg));
	reg.r_rip = (unsigned long int)remote_fd_map + 0x26c;
	ptrace_set_regs(pid, &reg);
	ptrace_cont(pid);
	printf("waiting stop\n");
	waitpro(pid, &status);
	print_regs(pid);
	printf("stop: %d\n", WSTOPSIG(status));
	/*  want to munmap allocated memory size. compel_syscall() use remote_map, so can't unmap address remote_map. Please, munmap in Parasite engine itself   */
	/* maybe, I think restore memory in compel_syscall, this routine is bad. */
	//compel_syscall(pid, &orig, 0xb, &ret, (unsigned long)remote_fd_map, 0x1000, 0x0, 0x0, 0x0, 0x0);
	//compel_syscall(pid, &orig, 0xb, &ret, (unsigned long)remote_map, 0x0, 0x0, 0x0, 0x0, 0x0);
	ptrace_set_regs(pid, &orireg);
	printf("restore reg\n");

	//ptrace_cont(pid);
	//while(1){}
	ptrace_detach(pid);

	return 0;
}
