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

#define LINUX_MAP_ANONYMOUS 0x20

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
	char buf[] = "/tmp/shm";
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
	//remote_fd_map = remote_mmap(pid, &orig, (void *) 0x0, sizeof(parasite_blob), PROT_EXEC | PROT_READ | PROT_WRITE, MAP_SHARED | LINUX_MAP_ANONYMOUS, 0x0, 0x0);
	remote_fd_map = remote_mmap(pid, &orig, (void *) 0x0, sizeof(parasite_blob), PROT_EXEC | PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FILE, remote_fd, 0x0);
	compel_syscall(pid, &orig, 0x3, &ret, (unsigned long)remote_fd, 0x0, 0x0, 0x0, 0x0, 0x0); 
	printf("remote_fd_map:%lx\n", (unsigned long int)remote_fd_map);
	
	local_map = mmap(0x0, sizeof(parasite_blob), PROT_EXEC | PROT_WRITE |PROT_READ, MAP_SHARED, fd, 0);
	if((int *)&local_map < 0){
		perror("mmap(2)");
	}
	printf("local_map:%p\n", local_map);
	//inject_syscall_buf(pid, (char *)parasite_blob, (unsigned long int)remote_fd_map, sizeof(parasite_blob));
	memcpy(local_map, parasite_blob, sizeof(parasite_blob));

/*// steping debug
 * while(1){
		print_regs(pid);
		printf("stop: %d\n", WSTOPSIG(status));
		sleep(1);
		ptrace_step(pid);
		waitpro(pid, &status);
	}
*/
	struct sockaddr_un saddr;
	//int sockfd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK, 0);
	int sockfd = socket(PF_LOCAL, SOCK_SEQPACKET, 0);
	saddr.sun_family = PF_LOCAL;
	snprintf(saddr.sun_path, UNIX_PATH_MAX, "crtools-pr-%d", getpid());
	//strncpy(saddr.sun_path, "testpath", 108);
	//strcpy(saddr.sun_path, "testpath");
	int socklen = sizeof(saddr);

	if(bind(sockfd, (struct sockaddr *)&saddr, socklen) < 0)
		perror("bind");
	
	if(listen(sockfd, 5) < 0)
		perror("listen");
	struct parasite_init args;
	//args.h_addr_len = sizeof(args.h_addr);
	args.h_addr_len = socklen;
	args.h_addr.sun_family = saddr.sun_family;
	strncpy(args.h_addr.sun_path, saddr.sun_path, sizeof(saddr.sun_path));
	//memcpy((void *)&args.h_addr, (void *)&saddr, sizeof(saddr));

	memcpy(local_map + parasite_sym__export_parasite_args, (void *)&args, sizeof(args));
	printf("%s\n", args.h_addr.sun_path);

	int clsock;
	//ptrace_cont(pid);
	ptrace_get_regs(pid, &reg);
	memcpy(&orireg, &reg, sizeof(reg));
	reg.r_rip = (unsigned long int)remote_fd_map;
	#define PARASITE_STACK_SIZE	(16 << 10)
	#define RESTORE_STACK_SIGFRAME 0 // Please Calc
	reg.r_rbp = (unsigned long int)remote_fd_map + sizeof(parasite_blob);
	reg.r_rbp += RESTORE_STACK_SIGFRAME;
	reg.r_rbp += PARASITE_STACK_SIZE;
	ptrace_set_regs(pid, &reg);
	ptrace_cont(pid);
	//parasite_run(pid, PT_CONTINUE, reg.r_rip, (void *)reg.r_rbp, &reg, &orig);
	printf("waiting\n");
	clsock = accept(sockfd, NULL, 0); 
	//int clsock = accept(sockfd, NULL, 0); 
	if(clsock < 0){
		perror("accept");
		sleep(1);
	}
	/*char ch[1024];
	read(clsock, ch, sizeof(ch));
	printf("client msg: %s\n", ch);
	strncpy(ch, "HELLO, I'm LOCAL\n", sizeof(ch));
	write(clsock, ch, sizeof(ch));
	*/
	struct ctl_msg m = { };
	parasite_wait_ack(clsock, PARASITE_CMD_INIT_DAEMON, &m);
	compel_rpc_call_sync(PARASITE_CMD_DUMP_THREAD, clsock);
	compel_rpc_call_sync(PARASITE_CMD_DUMP_ITIMERS, clsock);
	compel_rpc_call_sync(PARASITE_CMD_GET_PID, clsock);
	usleep(20);
	struct hello_pid *hellop = local_map + parasite_sym__export_parasite_args;
	printf("hello: %s\n", hellop->hello);
	printf("pid: %d\n", hellop->pid);
	compel_rpc_call_sync(PARASITE_CMD_FINI, clsock);
	printf("waiting stop\n");
	waitpro(pid, &status);
	printf("stop: %d\n", WSTOPSIG(status));
	print_regs(pid);
	
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
