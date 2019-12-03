#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PACKAGE 1
#include "breakpoint.h"
#include "common.h"
#include "fds.h"
#include "ptrace.h"
#include "parasite_syscall.h"
#include "register.h"
#include "setmem.h"
#include "soccr/soccr.h"
#include "files.h"
#include "protobuf.h"
#include "image.h"
#include "pagemap.h"
#include "vma.h"
#include "images/inventory.pb-c.h"
#include "images/mm.pb-c.h"
#include "images/fdinfo.pb-c.h"
#include "getmap.h"
#include "types.h"

#define IPFWDEL 1
#define PROT_ALL (PROT_EXEC | PROT_WRITE | PROT_READ)

struct restore_info {
	pid_t tpid;
	char rpath[128];
	pid_t rpid;
	int dfd;
	void *shared_local_map;
	void *shared_remote_map;
	int epoll_fd;
};

typedef struct {
        unsigned long int sig[1024/(8*sizeof(unsigned long int))];
}__linux_sigset_t;

struct linuxsigaction {
        void (*rt_sa_handler) (int);
        __linux_sigset_t rt_sa_mask;
        int rt_sa_flags;
        void (*rt_sa_restorer) (void);
};

int target(char *path, char* argv[]);

int target(char *path, char *argv[]){
	char *exec[] = {path, NULL};
	int ret;
	printf("CPID: %d\n", getpid());
	printf("command: %s\n", exec[0]);
	ptrace_traceme();

	ret = execvp(exec[0], exec);
	perror("execvp");
	exit(ret);
}

int restore_socket(int pid, int rfd) {
	
	int rst, fd;
	int dsize;
	char *queue;
	char srcaddr[20], dstaddr[20];
	char buf [256];
	int srcpt, dstpt;
	struct libsoccr_sk *so_rst;
	struct libsoccr_sk_data data = {};
	union libsoccr_addr addr, dst;

	fd = open_file(pid, "sock");

	read(fd, buf, sizeof(buf));
	strncpy(srcaddr, strtok(buf, ","), sizeof(srcaddr));
	srcpt = atoi(strtok(NULL, ","));
	strncpy(dstaddr, strtok(NULL, ","), sizeof(dstaddr));
	dstpt = atoi(strtok(NULL, ","));
	data.snd_wl1 = atoi(strtok(NULL, ","));
	data.snd_wnd = atoi(strtok(NULL, ","));
	data.max_window = atoi(strtok(NULL, ","));
	data.rcv_wnd = atoi(strtok(NULL, ","));
	data.rcv_wup = atoi(strtok(NULL, ","));
	data.mss_clamp = atoi(strtok(NULL, ","));
	data.outq_seq = strtol(strtok(NULL, ","), NULL, 16);
	data.outq_len = atoi(strtok(NULL, ","));
	data.inq_seq = strtol(strtok(NULL, ","), NULL, 16);
	data.inq_len = atoi(strtok(NULL, ","));
	data.unsq_len = atoi(strtok(NULL, ","));
	data.snd_scale = atoi(strtok(NULL, ","));
	close(fd);


	addr.v4.sin_family = AF_INET;
	addr.v4.sin_addr.s_addr = inet_addr(srcaddr);
	addr.v4.sin_port = htons(srcpt);

	dst.v4.sin_family = AF_INET;
	dst.v4.sin_addr.s_addr = inet_addr(dstaddr);
	dst.v4.sin_port = htons(dstpt);

	printf("create new socket\n");
	rst = socket(AF_INET, SOCK_STREAM, 0);

	dup2(rst, rfd);
	if (rst != rfd)
		close(rst);

//	while(1){}

	so_rst = libsoccr_pause(rfd);

	libsoccr_set_addr(so_rst, 1, &addr, 0);
	libsoccr_set_addr(so_rst, 0, &dst, 0);

	fd = open_file(pid, "sndq");
	queue = malloc(data.outq_len + 1);
	read(fd, queue, data.outq_len);
	libsoccr_set_queue_bytes(so_rst, TCP_SEND_QUEUE, queue, 0);
	close(fd);

	fd = open_file(pid, "rcvq");
	queue = malloc(data.inq_len + 1);
	read(fd, queue, data.inq_len);
	libsoccr_set_queue_bytes(so_rst, TCP_RECV_QUEUE, queue, 0);
	close(fd);
	

	printf("restore\n");
	dsize = sizeof(struct libsoccr_sk_data);
	libsoccr_restore(so_rst, &data, dsize);

	printf("resume so_rst\n");
	libsoccr_resume(so_rst);
// unfilter packet 
	printf("unfilter packet\n");
//	setipfw(IPFWDEL, "192.168.11.1", "192.168.11.30");
	setipfw(IPFWDEL, srcaddr, dstaddr);

	return 0;
}

int restore_fork(int filePid, char *exec_path){
	int status;
	int fd;
	int i;
	struct restore_fd_struct fds[1024];
	pid_t pid;
	
	pid = fork();
	if(pid < 0){
		perror("FORK");
		exit(1);
	}
	if(pid != 0){
		return pid;
	}

	pid = fork();
	if(pid < 0){
		perror("fork");
		exit(1);
	}

	if(pid != 0){
		waitpro(pid, &status);
		if(WIFSTOPPED(status))
			ptrace_detach(pid);
	}
	target(exec_path, NULL);
	return 0;
}

void restore_sigactions(struct restore_info *ri, int n_sigactions, SaEntry  **sa) {
	int sig;
	int i;
	SaEntry *e;
	struct orig orig;
	long ret;
	struct linuxsigaction *act = ri->shared_local_map;
	struct linuxsigaction a;

	int fd = open_file(ri->tpid, "mem");
	if (fd < 0 )
		perror("open");
	for (sig = 1, i = 0; sig <= n_sigactions; sig++) {
		memset(act, 0, sizeof(*act));
		e = sa[i++];
		act->rt_sa_handler = e->sigaction;
		act->rt_sa_flags = e->flags;
		act->rt_sa_restorer = e->restorer;
		if(&act->rt_sa_mask != NULL && e->mask != NULL)
			memcpy(act->rt_sa_mask.sig,  &e->mask, sizeof(act->rt_sa_mask.sig));
		compel_syscall(ri->tpid, &orig, 13, &ret,
				(unsigned long int)sig, (unsigned long int)ri->shared_remote_map, 0x0, 0x8, 0x0, 0x0);
	}
	printf("finished restore sigaction\n");
}

typedef union epoll_data {
	void *ptr;
	int fd;
	uint32_t u32;
	uint64_t u64;
} epoll_data_t;

struct epoll_event {
	uint32_t events;
	epoll_data_t data;
} __attribute__((__packed__));

#define EPOLL_CTL_ADD 1

void epoll_restore(pid_t pid, int fd) {
	struct orig orig;
	long ret;
	compel_syscall(pid, &orig, 213, &ret,
				1, 0x0, 0x0, 0x0, 0x0, 0x0);
	compel_syscall(pid, &orig, 33, &ret,
				ret, fd, 0x0, 0x0, 0x0, 0x0);
	printf("epoll instance fd %ld\n", ret);
}

void epoll_ctl_restore(struct restore_info *ri, pid_t pid, int epfd, int tfd, unsigned int events,
		void *data) {
	struct orig orig;
	long ret;
	struct epoll_event *ev = ri->shared_local_map;
	ev->events = 0x1;
	ev->data.ptr = data;
	compel_syscall(pid, &orig, 233, &ret,
			epfd, EPOLL_CTL_ADD, tfd, (unsigned long)ri->shared_remote_map, 0x0, 0x0);
	if (ret != 0)
		printf("failed epoll_ctl add epfd %d, tfd %d, ev %p %d\n", epfd, tfd, &ev, ret);
	
}

int restore_eventfd(struct restore_info *ri, FileEntry *fe, int fd) {
	struct orig orig;
	long ret;
	if (fe->type != FD_TYPES__EVENTFD)
		return -1;
	compel_syscall(ri->tpid, &orig, 284, &ret,
			fe->efd->counter, 0x0, 0x0, 0x0, 0x0, 0x0);
	compel_syscall(ri->tpid, &orig, 33, &ret,
			ret, fd, 0x0, 0x0, 0x0, 0x0);
}

struct so_in {
	uint16_t sin_family;
	uint16_t sin_port;
	struct in_addr sin_addr;
	char __pad[8];
};

int restore_inet_socket(struct restore_info *ri, FileEntry *fe, int fd) {
	struct orig orig;
	long ret;
	if (fe->type != FD_TYPES__INETSK)
		return -1;

	compel_syscall(ri->tpid, &orig, 41, &ret,
				fe->isk->family, fe->isk->type, 0x0, 0x0, 0x0, 0x0);
	int old_fd = ret;
	compel_syscall(ri->tpid, &orig, 33, &ret,
				ret, fd, 0x0, 0x0, 0x0, 0x0);
	// Different sockaddr_in between FreeBSD and Linux but these size are same
	struct so_in *in = ri->shared_local_map;
	bzero(in, sizeof(struct so_in));
	in->sin_family = fe->isk->family;
	in->sin_port = htons(ri->tpid);
	in->sin_addr.s_addr = htonl(INADDR_ANY);
	compel_syscall(ri->tpid, &orig, 49, &ret,
			old_fd, (unsigned long) ri->shared_remote_map, sizeof(struct sockaddr_in), 0x0, 0x0, 0x0);
	compel_syscall(ri->tpid, &orig, 50, &ret,
			old_fd, fe->isk->backlog, 0x0, 0x0, 0x0, 0x0);

}

int restore_regfile_fd(struct restore_info *ri, FileEntry *fe, int fd) {
	struct orig orig;
	long ret;
	int old_fd;
	if (fe->type != FD_TYPES__REG)
		return -1;

	memcpy(ri->shared_local_map, fe->reg->name, 128);
	compel_syscall(ri->tpid, &orig, 2, &ret,
				(unsigned long)ri->shared_remote_map, fe->reg->flags, fe->reg->mode, 0x0, 0x0, 0x0);
	old_fd = ret;
	compel_syscall(ri->tpid, &orig, 8, &ret,
				old_fd, fe->reg->pos, SEEK_SET, 0x0, 0x0, 0x0);
	if (old_fd == fd)
		return;
	compel_syscall(ri->tpid, &orig, 33, &ret,
				old_fd, fd, 0x0, 0x0, 0x0, 0x0);
	compel_syscall(ri->tpid, &orig, 3, &ret,
				old_fd, 0x0, 0x0, 0x0, 0x0, 0x0);
}

int restore_epoll(struct restore_info *ri, pid_t pid, pid_t rpid, int dfd) {
	int count = 0;
	int epoll_id;
	struct cr_img *img;
	TaskKobjIdsEntry *ids;
	int ret;
	EventpollTfdEntry *entry;
	FileEntry **fes, **base;
	FileEntry *fe;
	fes = base = malloc(sizeof(FileEntry)*20);

	img = open_image_at(dfd, CR_FD_FILES, O_RSTR);
	if (!img)
		return -1;

	while(1){

		ret = pb_read_one_eof(img, &fe, PB_FILE);
		if (ret <= 0)
			break;
		fes = base +(fe->id - 1)*sizeof(FileEntry);
		memcpy(fes, fe, sizeof(FileEntry));

	}
	close_image(img);

	img = open_image_at(dfd, CR_FD_IDS, O_RSTR, rpid);
	if (!img)
		return -1;

	pb_read_one_eof(img, &ids, PB_IDS);
	close_image(img);

	img = open_image_at(dfd, CR_FD_FDINFO, O_RSTR, ids->files_id);
	if (!img)
		return -1;

	while(1) {
		FdinfoEntry *e;
		ret = pb_read_one_eof(img, &e, PB_FDINFO);
		if (ret <= 0)
			break;
		fe = base + (e->id-1) * sizeof(FileEntry);
		switch (e->type) {
			case FD_TYPES__REG:
				restore_regfile_fd(ri, fe, e->fd);
				break;
			case FD_TYPES__INETSK:
				printf("File Entry INETSK id %d, src_port %d\n", fe->id, fe->isk->src_port);
		//		restore_inet_socket(ri, fe, e->fd);
				break;
			case FD_TYPES__EVENTPOLL:
				epoll_restore(pid, e->fd);
				ri->epoll_fd = e->fd;
				epoll_id = e->id;
				break;
			case FD_TYPES__EVENTFD:
				printf("File Entry EVENTFD FILE id %d, efd flag %d\n", fe->id, fe->efd->flags);
				restore_eventfd(ri, fe, e->fd);
				break;
			default:
				break;
		}
	}
	fe = base + (epoll_id-1)*sizeof(FileEntry);
	if (fe->epfd != NULL) {
		for(int i = 0; i < fe->epfd->n_tfd; i++){
			entry = fe->epfd->tfd[i];
			printf("File Entry EVENTPOLL FILE[%d] fd %d, events %ld, data %ld\n", i, entry->tfd, entry->events, entry->data);
			epoll_ctl_restore(ri, pid, ri->epoll_fd, entry->tfd, entry->events, entry->data);
		}
	}

	close_image(img);
	free(base);
}

int restore_process(struct restore_info *ri, int child) {
	pid_t pid = ri->tpid;
	char *rpath = ri->rpath;
	pid_t rpid = ri->rpid;
	int dfd = ri->dfd;
	int status;
	struct orig orig;
	struct remap_vm_struct revm[BUFSIZE];
	struct cr_img *img;
	InventoryEntry *he;
	CoreEntry *ce;

	struct linuxreg *linuxreg;


	insert_breakpoint(pid, rpath);
	waitpro(pid, &status);
	printf("stop: %d\n", WIFSTOPPED(status));
	struct vmds vmds;
	//remap_vm(pid, rpid, revm, &orig);
	
	img = open_image_at(dfd, CR_FD_INVENTORY, O_RSTR);
	if (!img)
		return -1;

	if (pb_read_one(img, &he, PB_INVENTORY) < 0)
		return -1;

	close_image(img);


	if (prepare_mm_pid(dfd, rpid, pid) < 0)
		return -1;

	prepare_mappings(dfd, rpid, pid);

	call_mremap(pid);

	int write_fd = open_file(pid, "mem");
	vdso_redirect(write_fd);
	close(write_fd);
	printf("vdso redirect\n");
	//setmems(pid, rpid, revm);

	alloc_restorer_mem(ri);

	img = open_image_at(dfd, CR_FD_CORE, O_RSTR, rpid);
	if (!img)
		return -1;
	if (pb_read_one(img, &ce, PB_CORE) < 0)
		return -1;
	restore_sigactions(ri, ce->tc->n_sigactions, ce->tc->sigactions);

	close_image(img);

	restore_epoll(ri, pid, rpid, dfd);

	free_restorer_mem(ri);

	if (!child)
		ce->thread_info->gpregs->ip += 0x2;
	printf("ip: %llx\n", ce->thread_info->gpregs->ip);

	setregs(pid, ce);

	return 0;

}

int listen_port(int port) {
	int sockpre;
	socklen_t size;
	struct sockaddr_in addr;
	int aux;
	
	sockpre = socket(AF_INET, SOCK_STREAM, 0);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);
	aux = 1;
	setsockopt(sockpre, SOL_SOCKET, SO_REUSEADDR, (const char *) &aux, sizeof(aux));
	size = sizeof(addr);
	bind (sockpre, (struct sockaddr *) &addr, size);

	if (listen(sockpre, 5) < 0){
		perror("listen");
		exit(1);
	}
	return sockpre;
}

int restore(struct restore_info* ri) {
	pid_t rpid = ri->rpid;
	char *rpath = ri->rpath;
	int dfd = ri->dfd;
	int status;
	pid_t pid, cpid;
	struct reg reg;

	printf("CMD : %s\n", rpath);
	printf("PPID: %d\n", getpid());
	printf("Restore file: %d\n", rpid); 
	
	int fd = listen_port(80);
	dup2(fd, 6);
	ri->tpid = restore_fork(rpid, rpath);
//	ptrace_attach(pid);
	waitpro(ri->tpid, &status);
	ptrace_attach(ri->tpid +1);
	waitpro(ri->tpid + 1, &status);
	restore_process(ri, 0);
	ri->tpid++;
	ri->rpid++;
	restore_process(ri, 1);
//	step_debug(pid);

	//ptrace_cont(pid);
//	sleep(10);
	
//	waitpro(pid, &status);
//	print_regs(pid);

	/*
	 * To keep attach
	 * if detach from process, uncomment ptrace_detach
	 */
//	while(1){}
	ri->tpid--;
	ptrace_detach(ri->tpid);
//	ptrace_cont(ri->tpid+1);
//	waitpro(ri->tpid+1, &status);
//	print_regs(ri->tpid+1);

//	step_debug(ri->tpid+1);
	ptrace_detach(ri->tpid+1);
//	printf("detach\n");
	
	return pid;
}

int cr_restore_tasks(int pid, char *rpath, int dfd){
	struct restore_info ri = {
		.rpid = pid,
		.dfd = dfd
	};
	if(strncpy(ri.rpath, rpath, sizeof(ri.rpath)) < 0)
		perror("strncpy");
	return restore(&ri);
}
