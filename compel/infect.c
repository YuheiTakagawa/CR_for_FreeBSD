#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/user.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <arpa/inet.h>

#include "common.h"
#include "emulate.h"
#include "infect.h"
#include "infect-priv.h"
#include "infect-rpc.h"
#include "parasite.h"
#include "parasite-head.h"
#include "parasite_syscall.h"
#include "ptrace.h"
#include "rpc-pie-priv.h"
#include "fdtransport.h"
#include "../soccr/soccr.h"
#include "files.h"

#define PROT_ALL (PROT_EXEC | PROT_WRITE | PROT_READ) 
#define PARASITE_STACK_SIZE	(16 << 10)
#define RESTORE_STACK_SIGFRAME 0 // TODO Calc SIGFRAMESIZE

#define IPFWADD 0

int parasite_drain_fds_seize(void *ctl, pid_t pid);

struct hello_pid{
	char hello[256];
	int pid;
};


struct linux_sockaddr_un{
	unsigned short sun_family;
	char sun_path[108];
};

struct parasite_init_args_linux{
	int32_t h_addr_len;
	struct linux_sockaddr_un h_addr;
};

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

void step_debug(int pid){
	// stepping debug printing registers infinity loop
	int status;
	while(1){
		print_regs(pid);
		printf("stop: %d\n", WSTOPSIG(status));
	//	sleep(1);
		ptrace_step(pid);
		waitpro(pid, &status);
		if(WSTOPSIG(status) == SIGBUS)
			break;
	}
}

void curing(struct parasite_ctl *ctl){
	compel_rpc_call_sync(PARASITE_CMD_FINI, ctl);
}

static inline void close_safe(int *pfd){
	if(*pfd > -1){
		close(*pfd);
		*pfd = -1;
	}
}

void *compel_parasite_args_p(struct parasite_ctl *ctl){
	return ctl->addr_args;
}

static int gen_parasite_saddr(struct sockaddr_un *saddr, int key){
	int sun_len;

	saddr->sun_family = PF_UNIX;
	/*
	 * X/crtools-pr-%d is not root in CRIU for Linux.
	 * Temporary, CRIU for FreeBSD has X/crtools-pr-%d to root.
	 */
	snprintf(saddr->sun_path, UNIX_PATH_MAX,
			"/X/crtools-pr-%d", key);

	sun_len = SUN_LEN(saddr);
	*(saddr->sun_path + sun_len) = '\0';

	return sun_len;
}

static int prepare_tsock(struct parasite_ctl *ctl, pid_t pid, 
	struct parasite_init_args_linux *args){
	int ssock = -1;
	//socklen_t sk_len;
	struct sockaddr_un addr;

	args->h_addr_len = gen_parasite_saddr(&addr, getpid());

	ssock = ctl->ictx.sock;
	//sk_len = sizeof(addr);
		
	if(ssock == -1){
		printf("err: No socket in ictx\n");
		goto err;
	}

	/* CRIU use getsockname and compare sizeof(naddr.sun_family) to sk_len.
	 * In FreeBSD, sizeof(naddr.sun_family) and sk_len are not equal,
	 * so getsockname is don't use in FreeBSD
	 */

	/*
	if(getsockname(ssock, (struct sockaddr *) &naddr, &sk_len) < 0){
		perror("Unable to get name for a socket");
		return -1;
	}
	*/

	if(bind(ssock, (struct sockaddr *) &addr, args->h_addr_len) < 0){
		perror("Can't  bind socket");
		goto err;
	}

	if(listen(ssock, 1)){
		perror("Can't listen on transport socket");
		goto err;
	}

	if(ctl->ictx.flags & INFECT_FAIL_CONNECT)
		args->h_addr_len = gen_parasite_saddr(&addr, getpid() + 1);

	/*
	 * For FreeBSD Linuxulator, 
	 * struct sockaddr_un is different between Linux and FreeBSD
	 */	

	args->h_addr.sun_family = addr.sun_family;
	strncpy(args->h_addr.sun_path, addr.sun_path, sizeof(addr.sun_path));

	//ctl->tsock = -ssock;
	ctl->tsock = ssock;
	return 0;
err:
	close_safe(&ssock);
	return -1;
}

static int parasite_init_daemon(struct parasite_ctl *ctl){
	struct parasite_init_args_linux *args;
	pid_t pid = ctl->rpid;
	int sockfd;
	struct ctl_msg m = { };
	struct reg reg;

	*ctl->addr_cmd = PARASITE_CMD_INIT_DAEMON;
	args = compel_parasite_args(ctl, struct parasite_init_args_linux);

	sockfd = ctl->ictx.sock;
	prepare_tsock(ctl, pid, args);

	ptrace_get_regs(pid, &reg);

	reg.r_rip = (unsigned long int)ctl->remote_map;
	reg.r_rbp = (unsigned long int)ctl->remote_map + sizeof(parasite_blob);
	printf("rbp: %lx\n", reg.r_rbp);
	reg.r_rbp += RESTORE_STACK_SIGFRAME;
	printf("rbp: %lx\n", reg.r_rbp);
	reg.r_rbp += PARASITE_STACK_SIZE;
	printf("rbp: %lx\n", reg.r_rbp);

	ptrace_set_regs(pid, &reg);
	ptrace_cont(pid);
//	step_debug(pid);
	/*
	 *  parasite_run include ptrace SETREGS and CONTINUE, 
	 *  but this function does not work properly. 
	 */
	//parasite_run(pid, PT_CONTINUE, reg.r_rip, (void *)reg.r_rbp, &reg, &orig);
	
	printf("connection waiting\n");

	ctl->tsock = accept(sockfd, NULL, 0); 
	if(ctl->tsock < 0){
		perror("accept");
		sleep(1);
	}

	/*
	 * waiting receive PARASITE_CMD_INIT_DAEMON from Parasite Engine
	 */
	parasite_wait_ack(ctl->tsock, PARASITE_CMD_INIT_DAEMON, &m);

	return 0;
}

static int make_sock_for(int pid){
	int sk = -1;

	/*
	 * This function is prepare injection parasite engine about networking.
	 * Ex) network namespace, setns
	 */


	//sk = socket(PF_LOCAL, SOCK_SEQPACKET | SOCK_NONBLOCK, 0);
	sk = socket(PF_UNIX, SOCK_SEQPACKET, 0);

	return sk;
}

int compel_cmds_run (struct parasite_ctl *ctl, int val){
	/*
	 * send CMD and wait ACK against CMD
	 */
	compel_rpc_call_sync(PARASITE_CMD_DUMP_THREAD, ctl);
	compel_rpc_call_sync(PARASITE_CMD_DUMP_ITIMERS, ctl);
	compel_rpc_call_sync(PARASITE_CMD_GET_PID, ctl);

	/*
	 * Wait for Parasite Engine finishes writing to memory.
	 * Good method is sync, lock, futex.
	 * Initial implementation is sleeping process.
	 * Second implementation is checking data as necessary,
	 * please implement per CMD.
	 * I want to implement as polling which especially
	 * value is changed.
	 */
	
	/* 
	 * return address is shared memory + args address
	 * 
	 */
	struct hello_pid *hellop; 
	hellop = (struct hello_pid*) ctl->addr_args;

	/*
	 * This is checking data as necessary
	 */
	while(!(isdigit(hellop->hello[0]) ||
			       	isalpha(hellop->hello[0])));

	printf("hello: %s\n", hellop->hello);
	printf("pid: %d\n", hellop->pid);


	if (val) {
		printf("tcpestablished\n");
		struct parasite_drain_fd pdfd;
		pdfd.nr_fds = 4;
       		ctl->addr_args = &pdfd;

		parasite_drain_fds_seize(ctl, ctl->rpid);
	}
	
	return 0;
}

int injection_clear(struct parasite_ctl *ctl, struct orig *orig) {
	int status;
	/*
	 * the last command of Parasite Daemon is int3.
	 */
	printf("waiting stop\n");
	waitpro(ctl->rpid, &status);
	printf("stop: %d\n", WSTOPSIG(status));
	//print_regs(ctl->rpid);

	
	/*  want to munmap allocated memory size.
	 *  compel_syscall() use remote_map, so can't
	 *  unmap address remote_map.
	 *  Please, munmap in Parasite engine itself 
	 */
	/* maybe, I think restore memory in compel_syscall, this routine is bad. */
	/*
	compel_syscall(pid, &orig, 0xb, &ret, (unsigned long)remote_fd_map, 0x1000, 0x0, 0x0, 0x0, 0x0);
	compel_syscall(pid, &orig, 0xb, &ret, (unsigned long)remote_map, 0x0, 0x0, 0x0, 0x0, 0x0);
	*/

	ptrace_set_regs(ctl->rpid, &orig->reg);
	printf("restore reg\n");

	return 0;
}

int parasite_drain_fds_seize(void *ctl, pid_t pid)
{
	/*
	struct libsoccr_sk_data data = {};
	struct libsoccr_sk *so;
	int sock, fd;
	char srcaddr[20], dstaddr[20];
	int srcpt, dstpt;
	int msg = 0, fds = 0;
	struct sockaddr_in addr;
	char *queue;
	int dsize = 0;
	socklen_t len = sizeof(addr);

	unlink("/local.sock2");
	sock = listen_gate("/local.sock2");

	compel_rpc_call(PARASITE_CMD_DRAIN_FDS, ctl);

	fds = recvfd(sock, &msg, sizeof(msg));
	printf("fds %d\n", fds);

	getsockname(fds, (struct sockaddr *)&addr, &len);
	strncpy(srcaddr, inet_ntoa(addr.sin_addr), sizeof(srcaddr));
	srcpt = ntohs(addr.sin_port);
	getpeername(fds, (struct sockaddr *)&addr, &len);
	strncpy(dstaddr, inet_ntoa(addr.sin_addr), sizeof(dstaddr));
	dstpt = ntohs(addr.sin_port);

	setipfw(IPFWADD, srcaddr, dstaddr);
	so = libsoccr_pause(fds);
	printf("pause\n");

	dsize = libsoccr_save(so, &data, sizeof(data));
	if(dsize < 0){
		perror("libsoccr_save");
		return 1;
	}
	close(fds);
	printf("close, don't send fin\n");

	queue = libsoccr_get_queue_bytes(so, TCP_RECV_QUEUE, 0);
	fd = open_dump_file(pid, "rcvq");
	write(fd, queue, data.inq_len);
	close(fd);

	queue = libsoccr_get_queue_bytes(so,  TCP_SEND_QUEUE, 0);
	fd = open_dump_file(pid, "sndq");
	write(fd, queue, data.outq_len);
	close(fd);


	printf("TCP repair mode: off\n");

	fd = open_dump_file(pid, "sock");
	dprintf(fd, "%s,%d,%s,%d,%u,%u,%u,%u,%u,%u,%x,%d,%x,%d,%d,%d\n",
			srcaddr, srcpt, dstaddr, dstpt,
			data.snd_wl1, data.snd_wnd,
			data.max_window, data.rcv_wnd, data.rcv_wup,
			data.mss_clamp, data.outq_seq, data.outq_len,
			data.inq_seq, data.inq_len, data.unsq_len, data.snd_scale);
	close(fd);

	compel_rpc_sync(PARASITE_CMD_DRAIN_FDS, ctl);
	libsoccr_close(so);
	libsoccr_resume(so);
	*/

	return 0;
}

int injection(pid_t pid, int *option){
	struct orig orig;
	struct parasite_ctl *ctl;
	struct infect_ctx *ictx;

	void *tmp_map;
	char buf[] = SHARED_FILE_PATH;

	int fd, sk;
	long remote_fd;

	long ret;

	int tcp_established = option[0];

	ctl = (struct parasite_ctl *) malloc(sizeof(struct parasite_ctl));

	ctl->rpid = pid;

	/*
	 * move make_sock_for to function compel_prepare
	 */
	ictx = &ctl->ictx;
	ictx->sock = make_sock_for(pid);
	

	/* 
	 *
	 * First, compel mmap syscall to open file for shared memory
	 * because target process isn't know the file path,
	 * so write to memory of target process file path. 
	 * Second, compel target process run mmap syscall map file for shared memory.
	 * Third, local process run mmap syscall to share memory.
	 */

	/*
	 * TODO
	 * remote_mmap and compel_syscall are passed arguments 'struct parasite_ctl', 
	 * however current implementation is passing value of pid. This is bad.
	 * If you want to fix this, you should changed
	 * CR_for_FreeBSD/src/include/freebsd/parasite_syscall.c
	 * and introduce struct parasite_ctl to getall.c, restore.c and etc...  */
	tmp_map = remote_mmap(ctl->rpid, &orig, (void *) 0x0,
		       	PAGE_SIZE, PROT_ALL, LINUX_MAP_ANONYMOUS | MAP_SHARED, 0x0, 0x0);
	printf("remote_map:%p\n", tmp_map);

	fd = open(buf, O_RDWR);
	printf("open file for shared memory: %s, fd: %d\n", buf, fd);
	
	inject_syscall_buf(ctl->rpid, buf, tmp_map, 0);
	compel_syscall(ctl->rpid, &orig, 0x2, &remote_fd,
		       	(unsigned long)tmp_map, O_RDWR, 0x0, 0x0, 0x0, 0x0);
	printf("remote_fd:%ld\n", remote_fd);

	ctl->remote_map = remote_mmap(ctl->rpid, &orig, (void *) 0x0, sizeof(parasite_blob),
		       	PROT_ALL, MAP_SHARED | MAP_FILE, remote_fd, 0x0);
	compel_syscall(ctl->rpid, &orig, 0x3, &ret, (unsigned long)remote_fd,
		       	0x0, 0x0, 0x0, 0x0, 0x0); 
	printf("remote_fd_map:%p\n", ctl->remote_map);
	
	ctl->local_map = mmap(0x0, sizeof(parasite_blob), PROT_ALL, MAP_SHARED, fd, 0);
	printf("local_map:%p\n", ctl->local_map);



	/*
	 * Injection Parasite Engine via shared memory.
	 *
	 */

	memcpy(ctl->local_map, parasite_blob, sizeof(parasite_blob));

	printf("size parasite_blob %x\n", sizeof(parasite_blob));
	printf("parasite_args %x\n", parasite_sym__export_parasite_args);

	/*
	 * If you want to debug register, please uncomment
	 */
	//step_debug(pid);



	/*
	 * Prepare communicate to Parasite Engine via socket
	 *
	 */
	ctl->addr_cmd = ctl->local_map + parasite_sym__export_parasite_cmd;
	ctl->addr_args = ctl->local_map + parasite_sym__export_parasite_args;
	parasite_init_daemon(ctl);

//	compel_cmds_run(ctl, tcp_established);

	/*
	 * send PARASITE_CMD_FINI to Parasite Daemon,
	 * Parasite Daemon run socket closing and curing.
	 */

	curing(ctl);
	
	injection_clear(ctl, &orig);

	return 0;
}


