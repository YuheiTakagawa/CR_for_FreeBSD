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
	/*
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
*/
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

	/*
	read_fd_list(filePid, fds);
	for(i = 0; fds[i].fd != -2 ; i++){
		printf("fd:%d, off:%ld, path:%s\n", fds[i].fd, fds[i].offset, fds[i].path);
*/
		/*
		 *  if restore tty info, have to implement restoring ttys
		 */
/*
		if(strstr(fds[i].path, "/dev/pts") == NULL){
			if((strstr(fds[i].path, "internet")) ||
				(strstr(fds[i].path, "socket"))){
				restore_socket(filePid, fds[i].fd);
				continue;
			}else if(!strcmp(fds[i].path, "local"))
				continue;
			fd = prepare_restore_files(fds[i].path, fds[i].fd, fds[i].offset);
		}
	}
	*/
	pid = fork();
	if(pid < 0){
		perror("fork");
		exit(1);
	}
//	if(pid == 0){
//		char *exec[] = {exec_path, NULL};
//		execvp(exec[0], exec);
//	}
	if(pid != 0){
		waitpro(pid, &status);
		if(WIFSTOPPED(status))
			ptrace_detach(pid);
	}
	target(exec_path, NULL);
	return 0;
}
#define PAGEMAP_ENTRY_SIZE_ESTIMATE 16


static void free_pagemaps(struct page_read *pr)
{
	int i;

	for (i = 0; i < pr->nr_pmes; i++)
		pagemap_entry__free_unpacked(pr->pmes[i], NULL);

	xfree(pr->pmes);
}

static int init_pagemaps(struct page_read *pr, int dfd, int pid) {
	PagemapHead *h;
	PagemapEntry **pmes = NULL;
	PagemapEntry *pme;

	off_t fsize;
	fsize = img_raw_size(pr->pmi);
	int nr_pmes = fsize / PAGEMAP_ENTRY_SIZE_ESTIMATE + 2;
	pr->pmes = xzalloc(nr_pmes * sizeof(*pmes));

	pr->nr_pmes = 0;
	pr->curr_pme = -1;
	for(int i = 0; i < nr_pmes; i++){
		if(pb_read_one_eof(pr->pmi, &pr->pmes[i], PB_PAGEMAP) <= 0){
			break;
		}
		pr->nr_pmes++;
		printf("addr %lx, pages %d, flags%d\n", pr->pmes[i]->vaddr, pr->pmes[i]->nr_pages, pr->pmes[i]->flags);
	}

	return 0;
}

static void close_page_read(struct page_read *pr){
	int ret;

	if (pr->pmi)
		close_image(pr->pmi);
	if (pr->pi)
		close_image(pr->pi);

	if (pr->pmes)
		free_pagemaps(pr);
}


static int advance(struct page_read *pr)
{
	pr->curr_pme++;
	if (pr->curr_pme >= pr->nr_pmes)
		return 0;

	pr->pe = pr->pmes[pr->curr_pme];
	pr->cvaddr = pr->pe->vaddr;

	return 1;
}

int read_pagemap_page(struct page_read *pr, unsigned long vaddr, int nr, void *buf, unsigned flags){
	int fd = img_raw_fd(pr->pi);
	ssize_t ret;
	size_t curr = 0;
	int len = nr * PAGE_SIZE;

	while(1) {
		ret = pread(fd, buf + curr, len - curr, pr->pi_off + curr);
		if (ret < 1) {
			printf("Can't read mapping page %zd", ret);
			return -1;
		}
		curr += ret;
		if (curr == len)
			break;
	}
	return 0;
}

int open_page_read_at(int dfd, unsigned long pid, struct page_read *pr, int pr_flags){
	int flags, i_typ;

	switch (pr_flags & PR_TYPE_MASK) {
		case PR_TASK:
			i_typ = CR_FD_PAGEMAP;
			break;
		default:
			return -1;
	}
	pr->pmi = open_image_at(dfd, i_typ, O_RSTR, pid);
	if (!pr->pmi)
		return -1;

	if (empty_image(pr->pmi)) {
		close_image(pr->pmi);
		return 0;
	}

	pr->pi = open_pages_image_at(dfd, O_RSTR, pr->pmi, &pr->pages_img_id);
	if (!pr->pi) {
		close_page_read(pr);
		return -1;
	}

	if (init_pagemaps(pr, dfd, pid)) {
		close_page_read(pr);
		return -1;
	}

	pr->read_pages = read_pagemap_page;
	pr->advance = advance;
	return 1;
}

static void insert_trampoline64(uintptr_t from, uintptr_t to, int fd)
{
	struct {
		u16	movabs;
		u64	imm64;
		u16	jmp_rax;
		u32	guards;
	} __packed jmp = {
		.movabs		= 0xb848,
		.imm64		= to,
		.jmp_rax	= 0xe0ff,
		.guards		= 0xcccccccc,
	};

	//memcpy((void *)from, &jmp, sizeof(jmp));
	lseek(fd, from, SEEK_SET);
	write(fd, &jmp, sizeof(jmp));
}

void vdso_redirect(int fd){

	insert_trampoline64(0x7ffff7ffa000 + 0xb50, 0x00007ffffffff540, fd);
	insert_trampoline64(0x7ffff7ffa000 + 0x600, 0x00007ffffffff520, fd);
	insert_trampoline64(0x7ffff7ffa000 + 0xe10, 0x00007ffffffff530, fd);
	insert_trampoline64(0x7ffff7ffa000 + 0xe30, 0x00007ffffffff550, fd);
}


int prepare_mappings(int dfd, pid_t rpid, pid_t pid){
	int ret;
	struct page_read pr;
	char buf[4096];
	unsigned long len;
	unsigned long va = 0;

	pr.pi_off = 0;
	pr.curr_pme = 0;
	pr.cvaddr = 0;
	pr.pe = NULL;
	int write_fd = open_file(pid, "mem");
	ret = open_page_read_at(dfd, rpid, &pr, PR_TASK);
	if (ret <= 0)
		return -1;
	while(1) {
		ret = pr.advance(&pr);
		if (ret <= 0){
			break;
		}
		for(int i = 0; i < pr.pe->nr_pages; i++){
			pr.read_pages(&pr, va, 1, buf, 0x0);
			if(lseek(write_fd, pr.pe->vaddr + i * PAGE_SIZE, SEEK_SET) < 0)
				perror("lseek");
			if(write(write_fd, buf, sizeof(buf))<0)
				perror("write");
			va += 1 * PAGE_SIZE;
			len = 1 * PAGE_SIZE;
			pr.pi_off += len;
		}
		pr.cvaddr += pr.pe->nr_pages * PAGE_SIZE;
	}
	close(write_fd);
	return 0;
}

struct rst_info {
	struct vm_area_list vmas;
	struct _MmEntry *mm;
};

void remap_mem2_mmap(pid_t pid, struct vma_area *vma) {
	long ret;
	int status;
	void *remote_map;
	struct orig orig;
	remote_map = remote_mmap(pid, &orig,
			vma->e->start, vma->e->end - vma->e->start, vma->e->prot, vma->e->flags | 0x20, 0x0, 0x0);
}

void remap_mem2_munmap(pid_t pid, struct vma_area *vma) {
	long ret;
	int status;
	void *remote_map;
	struct orig orig;
	compel_syscall(pid, &orig,
			11, &ret, vma->e->start, vma->e->end - vma->e->start, 0x0, 0x0, 0x0, 0x0);
}

void restore_library(int write_fd, char *path, unsigned long int addr, size_t size){
	int fd;
	void *buf;

	fd = open(path, O_RDONLY);
	buf = mmap(0x0, size, PROT_READ, MAP_FILE | MAP_PRIVATE, fd, 0);
	lseek(write_fd, addr, SEEK_SET);

	if (write(write_fd, buf, size) < 0) {
		perror("write");
	}
	close(fd);
	munmap(buf, size);
}

void call_mremap(pid_t pid) {
	unsigned long int addr;
	size_t size;
	int write_fd;

	write_fd = open_file(pid, "mem");
/**
	size = 0x1c2000;
	addr = 0x7ffff7a0e000;
*/
	addr = 0x7ffff73b6000;
	size = 0x7ffff7579000 - addr;

	restore_library(write_fd, "/compat/linux/usr/lib64/libc.so.6", addr, size);

	addr = 0x7ffff7ddb000;
	size = 0x7ffff7dfd000 - addr;

	restore_library(write_fd, "/compat/linux/usr/lib64/ld-2.17.so", addr, size);

	addr = 0x7ffff6fa0000;
	size = 0x7ffff6fac000 - addr;

	restore_library(write_fd, "/compat/linux/usr/lib64/libnss_files-2.17.so", addr, size);

	addr = 0x7ffff71b3000;
	size = 0x7ffff71b5000 - addr;

	restore_library(write_fd, "/compat/linux/usr/lib64/libfreebl3.so", addr, size);

	addr = 0x7ffff7784000;
	size = 0x7ffff778c000 - addr;

	restore_library(write_fd, "/compat/linux/usr/lib64/libcrypt-2.17.so", addr, size);

	addr = 0x7ffff79bb000;
	size = 0x7ffff79d2000 - addr;

	restore_library(write_fd, "/compat/linux/usr/lib64/libpthread-2.17.so", addr, size);

	addr = 0x7ffff7bd7000;
	size = 0x7ffff7bd9000 - addr;

	restore_library(write_fd, "/compat/linux/usr/lib64/libdl-2.17.so", addr, size);

	close(write_fd);
	

}

int prepare_mm_pid(int dfd, pid_t rpid, pid_t pid){
	int ret = -1, vn = 0;
	struct cr_img *img;
	struct rst_info *ri;
	long ret2;
	struct orig orig;

	ri = xzalloc(sizeof(*ri));
	//ri->mm = xzalloc(sizeof(struct _MmEntry));

	img = open_image_at(dfd, CR_FD_MM, O_RSTR, rpid);
	if (!img)
		return -1;
 
	ret = pb_read_one_eof(img, &ri->mm, PB_MM);
	close_image(img);
	if (ret <= 0)
		return ret;

	img = NULL;

	compel_syscall(pid, &orig,
			11, &ret2, 0x800949000, 0x801e03000- 0x800949000, 0x0,0x0,0x0,0x0);
	while (vn < ri->mm->n_vmas || img != NULL) {
		struct vma_area *vma;

		ret = -1;
		vma = alloc_vma_area();
		if (!vma)
			break;

		ret = 0;
		ri->vmas.nr++;
		if (!img)
			vma->e = ri->mm->vmas[vn++];
		printf("%lx-%lx: %lx, %lx\n", vma->e->start, vma->e->end, vma->e->prot, vma->e->flags);
		if (vma->e->start == 0x400000 || vma->e->start > 0x800000000000 || vma->e->end == 0x7ffffffff000)
			continue;
		remap_mem2_munmap(pid, vma);
	}
	ri->vmas.nr = 0;
	vn = 0;
	while (vn < ri->mm->n_vmas) {
		struct vma_area *vma;

		ret = -1;
		vma = alloc_vma_area();
		if (!vma){
			break;
		}
		ret = 0;
		ri->vmas.nr++;
		if (!img)
			vma->e = ri->mm->vmas[vn++];
		printf("%lx-%lx: %lx, %lx\n", vma->e->start, vma->e->end, vma->e->prot, vma->e->flags);
		if (vma->e->start == 0x400000 || vma->e->start > 0x800000000000 || vma->e->end == 0x7ffffffff000)
			continue;
		if (vma->e->prot == PROT_READ)
			vma->e->prot |= PROT_WRITE;
		vma->e->prot |= PROT_READ |PROT_WRITE|PROT_EXEC;
		remap_mem2_mmap(pid, vma);
	}
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

		/*
		switch(fe->type){
			case FD_TYPES__REG:
				printf("File Entry REG, id %d, path %s\n", fe->id, fe->reg->name);
				break;
			case FD_TYPES__INETSK:
				printf("File Entry INETSK id %d, src_port %d\n", fe->id, fe->isk->src_port);
				break;
			case FD_TYPES__UNIXSK:
				printf("File Entry UNIXSK id %d, ino %d\n", fe->id, fe->usk->ino);
				break;
			case FD_TYPES__EVENTPOLL:
				epoll_restore(pid, 8);
				for(int i = 0; i < fe->epfd->n_tfd; i++){
					entry = fe->epfd->tfd[i];
					printf("File Entry EVENTPOLL FILE[%d] fd %d, events %ld, data %ld\n", i, entry->tfd, entry->events, entry->data);
		//			epoll_ctl_restore(pid, 8, tmp->tfd, tmp->events, tmp->data);
				}
				break;
			case FD_TYPES__EVENTFD:
				printf("File Entry EVENTFD FILE id %d, efd flag %d\n", fe->id, fe->efd->flags);
				break;
			default:
				break;
		}
		count++;
		*/
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
				restore_inet_socket(ri, fe, e->fd);
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

void free_restorer_mem(struct restore_info *ri) {
	long ret;
	struct orig orig;
	pid_t pid = ri->tpid;


	compel_syscall(pid, &orig, 0xb, &ret,
			(unsigned long)ri->shared_remote_map, PAGE_SIZE, 0x0, 0x0, 0x0, 0x0);
	munmap(ri->shared_local_map, PAGE_SIZE);

	ri->shared_remote_map = NULL;
	ri->shared_local_map = NULL;
}

void alloc_restorer_mem(struct restore_info *ri){
	pid_t pid = ri->tpid;
	long ret;
	long remote_fd;
	char buf[] = SHARED_FILE_PATH;
	struct orig orig;
	void *tmp_map = remote_mmap(pid, &orig, (void *) 0x0,
			PAGE_SIZE, PROT_ALL, 0x20 | MAP_SHARED, 0x0, 0x0);
	int fd = open(buf, O_RDWR);
	inject_syscall_buf(pid, buf, tmp_map, 0);
	compel_syscall(pid, &orig, 0x2, &remote_fd,
			(unsigned long)tmp_map, O_RDWR, 0x0, 0x0, 0x0, 0x0);

	ri->shared_remote_map = remote_mmap(pid, &orig, (void *) 0x0, PAGE_SIZE,
			PROT_ALL, MAP_SHARED | MAP_FILE, remote_fd, 0x0);
	compel_syscall(pid, &orig, 0x3, &ret, (unsigned long) remote_fd,
			0x0, 0x0, 0x0, 0x0, 0x0);
	compel_syscall(pid, &orig, 0xb, &ret,
			(unsigned long)tmp_map, PAGE_SIZE, 0x0, 0x0, 0x0, 0x0);
	ri->shared_local_map = mmap(0x0, PAGE_SIZE, PROT_ALL, MAP_SHARED, fd, 0);
	
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

//	printf("he fdinfo %d\n", he->has_fdinfo_per_id);
//	printf("he imgv %d\n", he->img_version);
//	printf("he root ids vm %d\n", he->root_ids->vm_id);
//	printf("he lsmtype %d\n", he->lsmtype);

	close_image(img);


	if (prepare_mm_pid(dfd, rpid, pid) < 0)
		return -1;

	prepare_mappings(dfd, rpid, pid);
//	unsigned long int ko;
//	int read_fd = open_file(pid, "mem");
//	lseek(read_fd, 0x7fffffffe1d8, SEEK_SET);
//	read(read_fd, &ko, sizeof(ko));
//	printf("%lx\n", ko);
//	close(read_fd);

	call_mremap(pid);

	int write_fd = open_file(pid, "mem");
	vdso_redirect(write_fd);
	close(write_fd);
	printf("vdso redirect\n");
	//setmems(pid, rpid, revm);
	int read_fd = open_file(ri->tpid, "mem");
	long long gaddress;
	lseek(read_fd, 0x9c6544, SEEK_SET);
	read(read_fd, &gaddress, sizeof(gaddress));
//	printf("event size %ld\n", sizeof(temp));
//	printf("event size %ld\n", sizeof(temp.data));
//	printf("temp p +0xn %lx\n", (struct epoll_event*)((char*)&temp+8));
//	printf("temp data p %p\n", &temp.data);
//	printf("temp data x %llx\n", temp.data);
//	printf("temp x +0xn %llx\n", *(struct epoll_event*)((char*)&temp+12));
//	printf("temp ptr %llx\n", temp.data.ptr);
//	printf("temp +0x0 %llx\n", temp.data.fd);
	printf("\n aaaaaaaaa address %llx\n", gaddress);
	//printf("temp +0x8 %08lx\n", *(&temp+0x8));
	close(read_fd);

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

	setregs(pid, ce);

	return 0;

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
/*
	step_debug(ri->tpid+1);
	int read_fd = open_file(ri->tpid + 1, "mem");
	struct epoll_event temp;
	lseek(read_fd, 0x9c6548, SEEK_SET);
	read(read_fd, &temp.data, sizeof(temp.data));
	printf("event size %ld\n", sizeof(temp));
	printf("event size %ld\n", sizeof(temp.data));
	printf("temp p +0xn %lx\n", (struct epoll_event*)((char*)&temp+8));
	printf("temp data p %p\n", &temp.data);
	printf("temp data x %llx\n", temp.data);
	printf("temp x +0xn %llx\n", *(struct epoll_event*)((char*)&temp+12));
	printf("temp ptr %llx\n", temp.data.ptr);
	printf("temp +0x0 %llx\n", temp.data.fd);
	printf("temp data +0x8 %lx\n", *(&temp.data));
	//printf("temp +0x8 %08lx\n", *(&temp+0x8));
	close(read_fd);
	
*/


//	step_debug(ri->tpid+1);
	ptrace_detach(ri->tpid+1);
//	printf("detach\n");
	
	return pid;
}
	
/*
int main(int argc, char* argv[]){
	int rpid;
	char *rpath;

	if(argc < 3){
		printf("Usage: %s <path> <file pid>\n", argv[0]);
		exit(1);
	}

	rpath = argv[1];
	rpid = atoi(argv[2]);

	restore(rpid, rpath);
	return 0;
}
*/

//int cr_restore_tasks(void) {
int cr_restore_tasks(int pid, char *rpath, int dfd){
	struct restore_info ri = {
		.rpid = pid,
		.dfd = dfd
	};
	if(strncpy(ri.rpath, rpath, sizeof(ri.rpath)) < 0)
		perror("strncpy");
	return restore(&ri);
}
