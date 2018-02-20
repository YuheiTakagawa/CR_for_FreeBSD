#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "parasite_syscall.c"
#include "ptrace.h"
#include "register.c"
#include "parasite-head.h"
#include "rpc-pie-priv.h"
#include "parasite.h"
#include "infect-rpc.h"
#include "infect-priv.h"

#define LINUX_MAP_ANONYMOUS 0x20 //ANONYMOUS of FreeBSD is 0x200, ANONYMOUS of Linux is 0x20
#define PROT_ALL (PROT_EXEC | PROT_WRITE | PROT_READ) 
#define PARASITE_STACK_SIZE	(16 << 10)
#define RESTORE_STACK_SIGFRAME 0 // Please Calc

struct hello_pid{
	char hello[256];
	int pid;
};


struct linux_sockaddr_un{
	unsigned short sun_family;
	char sun_path[108];
};

struct parasite_init{
	int32_t h_addr_len;
	struct linux_sockaddr_un h_addr;
};

void inject_syscall_buf(int pid, char *buf, unsigned long int addr, int size){
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

void step_debug(int pid){
	// stepping debug printing registers infinity loop
	int status;
	while(1){
		print_regs(pid);
		printf("stop: %d\n", WSTOPSIG(status));
		sleep(1);
		ptrace_step(pid);
		waitpro(pid, &status);
	}
}

static int parasite_init_daemon(int pid, unsigned long int local_map, unsigned long int remote_fd_map, struct reg *orireg){
	struct parasite_init args;
	struct sockaddr_un saddr;
	int sockfd, clsock;
	int socklen;
	struct ctl_msg m = { };
	struct hello_pid *hellop; 
	struct reg reg;

	//sockfd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK, 0); //SOCK_NONBLOCK 
	sockfd = socket(PF_LOCAL, SOCK_SEQPACKET, 0);

	saddr.sun_family = PF_LOCAL;
	snprintf(saddr.sun_path, UNIX_PATH_MAX, "crtools-pr-%d", getpid());
	
	socklen = sizeof(saddr);

	if(bind(sockfd, (struct sockaddr *)&saddr, socklen) < 0)
		perror("bind");
	
	if(listen(sockfd, 5) < 0)
		perror("listen");

	args.h_addr_len = socklen;
	args.h_addr.sun_family = saddr.sun_family;
	strncpy(args.h_addr.sun_path, saddr.sun_path, sizeof(saddr.sun_path));

	memcpy((void *)(local_map + parasite_sym__export_parasite_args), (void *)&args, sizeof(args));

	ptrace_get_regs(pid, &reg);
	memcpy(orireg, &reg, sizeof(*orireg));

	reg.r_rip = remote_fd_map;
	reg.r_rbp = remote_fd_map + sizeof(parasite_blob);
	reg.r_rbp += RESTORE_STACK_SIGFRAME;
	reg.r_rbp += PARASITE_STACK_SIZE;

	ptrace_set_regs(pid, &reg);
	ptrace_cont(pid);
	/*
	 *  parasite_run include ptrace SETREGS and CONTINUE, 
	 *  but this function does not work properly. 
	 */
	//parasite_run(pid, PT_CONTINUE, reg.r_rip, (void *)reg.r_rbp, &reg, &orig);
	
	printf("connection waiting\n");

	clsock = accept(sockfd, NULL, 0); 
	if(clsock < 0){
		perror("accept");
		sleep(1);
	}

	/*
	 * waiting receive PARASITE_CMD_INIT_DAEMON from Parasite Engine
	 */
	parasite_wait_ack(clsock, PARASITE_CMD_INIT_DAEMON, &m);

	/*
	 * send CMD and wait ACK against CMD
	 */
	compel_rpc_call_sync(PARASITE_CMD_DUMP_THREAD, clsock);
	compel_rpc_call_sync(PARASITE_CMD_DUMP_ITIMERS, clsock);
	compel_rpc_call_sync(PARASITE_CMD_GET_PID, clsock);


	/*
	 * Wait for Parasite Engine finishes writing to memory.
	 * Good method is sync, lock, futex.
	 * Now implement is sleeping process
	 */
	usleep(20);

	/* 
	 * return address is shared memory + args address
	 */
	hellop = (void *)(local_map + parasite_sym__export_parasite_args);

	printf("hello: %s\n", hellop->hello);
	printf("pid: %d\n", hellop->pid);


	/*
	 * send PARASITE_CMD_FINI to Parasite Daemon,
	 * Parasite Daemon run socket closing and curing.
	 */
	compel_rpc_call_sync(PARASITE_CMD_FINI, clsock);
}


int main(int argc, char *argv[]){

	if(argc < 2){

		printf("usage: ./injection <PID>\n");
		exit(1);

	}


	struct orig orig;
	struct reg reg, orireg;

	
	void *remote_map, *remote_fd_map, *local_map;
	char buf[] = "/tmp/shm";

	int fd;
	long remote_fd;

	long ret;

	int status;
	int pid;

       	pid = atoi(argv[1]);

	ptrace_attach(pid);
	waitpro(pid, &status);


	/* 
	 *
	 * First, compel mmap syscall to open file for shared memory
	 * because target process isn't know the file path,
	 * so write to memory of target process file path. 
	 * Second, compel target process run mmap syscall map file for shared memory.
	 * Third, local process run mmap syscall to share memory.
	 */

	remote_map = remote_mmap(pid, &orig, (void *) 0x0,
		       	PAGE_SIZE, PROT_ALL, LINUX_MAP_ANONYMOUS | MAP_SHARED, 0x0, 0x0);
	printf("remote_map:%lx\n", (off_t)remote_map);

	fd = open(buf, O_RDWR);
	printf("open file for shared memory: %s, fd: %d\n", buf, fd);
	
	inject_syscall_buf(pid, buf, (unsigned long int)remote_map, 0);
	compel_syscall(pid, &orig, 0x2, &remote_fd,
		       	(unsigned long)remote_map, O_RDWR, 0x0, 0x0, 0x0, 0x0);
	printf("remote_fd:%ld\n", remote_fd);

	remote_fd_map = remote_mmap(pid, &orig, (void *) 0x0, sizeof(parasite_blob),
		       	PROT_ALL, MAP_SHARED | MAP_FILE, remote_fd, 0x0);
	compel_syscall(pid, &orig, 0x3, &ret, (unsigned long)remote_fd,
		       	0x0, 0x0, 0x0, 0x0, 0x0); 
	printf("remote_fd_map:%lx\n", (unsigned long int)remote_fd_map);
	
	local_map = mmap(0x0, sizeof(parasite_blob), PROT_ALL, MAP_SHARED, fd, 0);
	if((int *)&local_map < 0){
		perror("mmap(2)");
	}
	printf("local_map:%p\n", local_map);



	/*
	 * Injection Parasite Engine via shared memory.
	 *
	 */

	memcpy(local_map, parasite_blob, sizeof(parasite_blob));


	/*
	 * If you want to debug register, please uncomment
	 */
	//step_debug(pid);



	/*
	 * Prepare communicate to Parasite Engine via socket
	 *
	 */
	parasite_init_daemon(pid, (unsigned long int)local_map, (unsigned long int)remote_fd_map, &orireg);

	/*
	 * the last command of Parasite Daemon is int3.
	 */
	printf("waiting stop\n");
	waitpro(pid, &status);
	printf("stop: %d\n", WSTOPSIG(status));
	print_regs(pid);

	
	/*  want to munmap allocated memory size.
	 *  compel_syscall() use remote_map, so can't
	 *  unmap address remote_map.
	 *  Please, munmap in Parasite engine itself 
	 */
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
