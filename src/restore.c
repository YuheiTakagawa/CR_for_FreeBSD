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
#include "getmap.h"

#define IPFWDEL 1


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
	int nr_pmes = fsize / PAGEMAP_ENTRY_SIZE_ESTIMATE + 1;
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
		printf("pme %lx\n", pr.pe->vaddr);
		for(int i = 0; i < pr.pe->nr_pages; i++){
			pr.read_pages(&pr, va, 1, buf, 0x0);
			lseek(write_fd, pr.pe->vaddr + i * PAGE_SIZE, SEEK_SET);
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
	printf("remote_map: %p\n", remote_map);
	ptrace_cont(pid);
	waitpro(pid, &status);
	printf("stopped: %d\n", WSTOPSIG(status));

}

void remap_mem2_munmap(pid_t pid, struct vma_area *vma) {
	long ret;
	int status;
	void *remote_map;
	struct orig orig;
	compel_syscall(pid, &orig,
			11, &ret, vma->e->start, vma->e->end - vma->e->start, 0x0, 0x0, 0x0, 0x0);
	ptrace_cont(pid);
	waitpro(pid, &status);
	printf("stopped: %d\n", WSTOPSIG(status));

}

#define MREMAP_MAYMOVE	1
#define MREMAP_FIXED	2

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
	long ret;
	int status;
	struct orig orig;
	void *buf;

	unsigned long int old_addr, new_addr, remote_map;
	size_t old_size, new_size;
	int flags = MREMAP_MAYMOVE | MREMAP_FIXED;
	old_size = 0x1c2000;
	new_size = 0x1c2000;
	old_addr = 0x800a00000;
	new_addr = 0x7ffff7a0e000;

	int write_fd = open_file(pid, "mem");

	restore_library(write_fd, "/compat/linux/usr/lib64/libc.so.6", new_addr, new_size);

	new_addr = 0x7ffff7ddb000;
	new_size = 0x7ffff7dfd000 - new_addr;

	restore_library(write_fd, "/compat/linux/usr/lib64/ld-2.17.so", new_addr, new_size);

}

int prepare_mm_pid(int dfd, pid_t rpid, pid_t pid){
	int ret = -1, vn = 0;
	struct cr_img *img;
	struct rst_info *ri;

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
		remap_mem2_mmap(pid, vma);
	}
	return 0;
}

int restore(pid_t rpid, char *rpath, int dfd){
	int status;
	pid_t pid;
	struct orig orig;
	struct remap_vm_struct revm[BUFSIZE];
	struct cr_img *img;
	InventoryEntry *he;
	CoreEntry *ce;

	printf("CMD : %s\n", rpath);
	printf("PPID: %d\n", getpid());
	printf("Restore file: %d\n", rpid); 
	
	pid = restore_fork(rpid, rpath);
	insert_breakpoint(pid, rpath);
	struct vmds vmds;
	//remap_vm(pid, rpid, revm, &orig);
	waitpro(pid, &status);
	show_vmmap(pid, &vmds);

	
	img = open_image_at(dfd, CR_FD_INVENTORY, O_RSTR);
	if (!img)
		return -1;

	if (pb_read_one(img, &he, PB_INVENTORY) < 0)
		return -1;

	printf("he fdinfo %d\n", he->has_fdinfo_per_id);
	printf("he imgv %d\n", he->img_version);
	printf("he root ids vm %d\n", he->root_ids->vm_id);
	printf("he lsmtype %d\n", he->lsmtype);

	close_image(img);


	if (prepare_mm_pid(dfd, rpid, pid) < 0)
		return -1;

	prepare_mappings(dfd, rpid, pid);
	call_mremap(pid);

	//setmems(pid, rpid, revm);

	
	img = open_image_at(dfd, CR_FD_CORE, O_RSTR, rpid);
	if (!img)
		return -1;
	if (pb_read_one(img, &ce, PB_CORE) < 0)
		return -1;
	printf("ce %lx\n", ce->thread_info->gpregs->r15);
	
	close_image(img);

	setregs(pid, ce);
//	step_debug(pid);

	ptrace_cont(pid);
//	sleep(10);
	
	waitpro(pid, &status);
	print_regs(pid);

	/*
	 * To keep attach
	 * if detach from process, uncomment ptrace_detach
	 */
	while(1){}
	ptrace_detach(pid);
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
	return restore(pid, rpath, dfd);
}
