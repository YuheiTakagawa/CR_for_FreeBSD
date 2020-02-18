#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/wait.h>

#include "common.h"
#include "fds.h"
#include "parasite_syscall.h"
#include "register.h"
#include "setmem.h"
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

