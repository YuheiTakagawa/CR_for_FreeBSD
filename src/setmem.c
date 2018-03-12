#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdio.h>

#include "ptrace.h"
#include "files.h"
#include "getmap.h"
#include "parasite_syscall.h"
#include "common.h"
#include "emulate.h"
#include "setmem.h"

int setmems(pid_t pid, pid_t filePid, struct remap_vm_struct *revm){
        int write_fd;
        int read_fd;

        write_fd = open_file(pid, "mem");
        
	while(revm->flags != 0x1){
		revm++;
	}

        read_fd = open_file(filePid, "data");
        write_mem(read_fd, write_fd, revm->new_addr); 

	while(revm->flags != 0x20){
		revm++;
	}
        read_fd = open_file(filePid, "stack");
        write_mem(read_fd, write_fd, revm->new_addr);

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

void remap_mem(pid_t pid, struct remap_vm_struct *revm, struct remap_vm_old *revm_old, struct orig *orig){
	long ret;
	int status;
	void *remote_map;
	while(revm->flags != 0x20){
		revm++;
	}
	compel_syscall(pid, orig,
			11, &ret, revm_old->old_addr, revm_old->old_size, 0x0, 0x0, 0x0, 0x0);
	ptrace_cont(pid);
	waitpro(pid, &status);
	printf("sig stopped: %d\n", WSTOPSIG(status));
	remote_map = remote_mmap(pid, orig,
			(void *)revm->new_addr, revm->new_end - revm->new_addr, revm->protection, LINUX_MAP_ANONYMOUS | MAP_SHARED, 0x0, 0x0);
	printf("remote_map:%p\n", remote_map);
	ptrace_cont(pid);
}

void read_vmmap_list(pid_t filePid, struct remap_vm_struct *revm){
	int read_fd;
	char buf[BUFSIZE];
	int i = 0;
	read_fd = open_file(filePid, "map");
	while(read(read_fd, &buf[i++], sizeof(char))){
		if(buf[i-1] == '\n'){
			buf[i-1] = '\0';
			revm->new_addr = strtol(strtok(buf, ","), NULL, 16);
			revm->new_end = strtol(strtok(NULL, ","), NULL ,16);
		       	revm->flags = strtol(strtok(NULL, ","), NULL, 16);
			revm->protection = strtol(strtok(NULL, ","), NULL, 16);
			strncpy(revm->path, strtok(NULL, ","), i);
			printf("read begin: %lx, end: %lx, flag: %x, prot: %x, path: %s\n", revm->new_addr, revm->new_end, revm->flags, revm->protection, revm->path);
			revm++;
			i = 0;
		}
	}
	close(read_fd);
}

void remap_vm(pid_t pid, pid_t filePid, struct remap_vm_struct *revm, struct orig *orig){
	int status;
	waitpro(pid, &status);
	printf("sig stopped: %d\n", WSTOPSIG(status));
	struct vmds vmds;
	struct remap_vm_old revm_old;
	read_vmmap_list(filePid, revm);
	show_vmmap(pid, &vmds);
	revm_old.old_addr = vmds.saddr;
	revm_old.old_size = vmds.ssize;
	remap_mem(pid, revm, &revm_old, orig);
}

