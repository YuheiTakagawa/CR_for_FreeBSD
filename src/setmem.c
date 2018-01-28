#ifndef SETMEM
#define SETMEM

#include <unistd.h>

#include "files.h"
#include "getmap.c"
#include "parasite_syscall.c"

#define BUFSIZE 1024
#define PATHBUF 30

struct remap_vm_struct{
	unsigned long int old_addr;
	unsigned long int old_size;
	unsigned long int new_addr;
	unsigned long int new_size;
};

int setmems(pid_t, pid_t, unsigned long int);
int write_mem(int, int, long int);

int setmems(pid_t pid, pid_t filePid, unsigned long int stack_addr){
        int write_fd;
        int read_fd;

        write_fd = open_file(pid, "mem");
        

        read_fd = open_file(filePid, "data");
        write_mem(read_fd, write_fd, 0x6c9000); 

        read_fd = open_file(filePid, "stack");
        write_mem(read_fd, write_fd, stack_addr);

        close(write_fd);
        return 0;
}

int write_mem(int read_fd, int write_fd, long int offset){
        char buf[BUFSIZE];
        int rnum;

        lseek(write_fd, offset, SEEK_SET);

        while(1){

                rnum = read(read_fd, buf, sizeof(buf));
                if(rnum > 0){
                        write(write_fd, buf, rnum);
                }else{
                        close(read_fd);
                        break;
                }
        }
        return rnum;
}

void remap_mem(int pid, struct remap_vm_struct * revm, struct orig *orig){
	long ret;
	int status;
	void *remote_map;

	compel_syscall(pid, orig,
			11, &ret, revm->old_addr, revm->old_size, 0x0, 0x0, 0x0, 0x0);
	ptrace_cont(pid);
	waitpro(pid, &status);
	remote_map = remote_mmap(pid, orig,
			(void *)revm->new_addr, revm->new_size, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | LINUX_MAP_ANONYMOUS, 0x0, 0x0);
	printf("remote_map:%p\n", remote_map);
	ptrace_cont(pid);
}

void remap_vm(int pid, unsigned long int new_addr, unsigned long int new_size, struct orig *orig){
	int status;
	waitpro(pid, &status);
	struct vmds vmds;
	struct remap_vm_struct revm;
	get_vmmap(pid, &vmds);
	revm.old_addr = vmds.saddr;
	revm.old_size = vmds.ssize;
	revm.new_addr = new_addr;
	revm.new_size = new_size;
	remap_mem(pid, &revm, orig);
}

#endif
