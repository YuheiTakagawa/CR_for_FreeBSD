#include <stdio.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <sys/mman.h>

#include "register.c"
#include "setmem.c"
#include "ptrace.h"
#include "parasite_syscall.c"
#include "getmap.c"

#define BUFSIZE 1024
#define PATHBUF 30

#ifdef __x86_64__
typedef uint64_t Elf_Addr;
typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Shdr Elf_Shdr;
typedef Elf64_Sym  Elf_Sym;
#else
typedef uint32_t Elf_Addr;
typedef Elf32_Ehdr Elf_Ehdr;
typedef Elf32_Shdr Elf_Shdr;
typedef Elf32_Sym  Elf_Sym;
#endif

struct restore_fd_struct{
	char *path;
	int fd;
	off_t offset;
};

int target(char *path, char* argv[]);
Elf64_Addr get_entry_point(char* filepath);

void prepare_change_stack(int pid, unsigned long int old_addr,
	        unsigned long int old_size, struct orig *orig){
	long ret;
	compel_syscall(pid, orig,
		11, &ret, old_addr, old_size, 0x0, 0x0, 0x0, 0x0);
}

unsigned long int change_stack(int pid, unsigned long int new_addr,
	       	unsigned long int new_size, struct orig *orig){
	restore_orig(pid, orig);
	void *remote_map;
	remote_map = remote_mmap(pid, orig, 
			(void *)new_addr, new_size, PROT_READ | PROT_WRITE,
	       	MAP_PRIVATE | LINUX_MAP_ANONYMOUS, 0x0, 0x0);
	printf("remote_map:%p\n", remote_map);
	return new_addr;
}

int prepare_restore_files(char *path, int fd, off_t foff){
	printf("PATH:%s\n", path);
	int tmp = open("/dump/hello", O_RDWR);
	if(fd != tmp){
		fd = dup2(tmp, fd);
		close(tmp);
	}
	lseek(fd, foff, SEEK_SET);
	return fd;	
}

int restore_fork(char *exec_path, struct restore_fd_struct *fds){
	pid_t pid;
	int fd;
	fd = prepare_restore_files(fds->path, fds->fd, fds->offset);
	printf("get fd: %d\n", fd);

	pid = fork();
	if(pid < 0){
		perror("FORK");
		exit(1);
	}
	if(pid != 0){
		close(fd);
		return pid;
	}
	target(exec_path, NULL);
	return 0;
}

int main(int argc, char* argv[]){
	int pid, filePid;
	int status;
	int flag = 0;
	char *filepath;
	Elf64_Addr entry_point;
	unsigned long int stack_addr;
	unsigned long int stack_size;
	struct restore_fd_struct fds;
	struct orig orig;
	struct vmds vmds;

	if(argc < 5){
		printf("Usage: %s <path> <file pid> <stack addr> <file offset>\n", argv[0]);
		exit(1);
	}

	filepath = argv[1];
	filePid = atoi(argv[2]);

	stack_addr = strtol(argv[3], NULL, 16);
	stack_size = 0x20000;
	if(stack_addr != 0x7ffffffdf000){
		stack_size = 0x21000;
	}
	fds.offset = strtol(argv[4], NULL, 16);
	printf("CMD : %s\n", argv[1]);
	printf("PPID: %d\n", getpid());
	printf("Restore file: %d\n", filePid); 

	fds.path = "/dump/hello";
	fds.fd = 3;
	pid = restore_fork(filepath, &fds);
			waitpro(pid, &status);
					entry_point = get_entry_point(filepath);
					ptrace_read_i(pid, entry_point);
					ptrace_write_i(pid, entry_point, 0xCC);
					ptrace_cont(pid);
					flag++;
			waitpro(pid, &status);
					get_vmmap(pid, &vmds);
					printf("finished setting registers\n");
					prepare_change_stack(pid, vmds.saddr, vmds.ssize, &orig);
					printf("prepare changed stack position in memory layout\n");
					ptrace_cont(pid);
			waitpro(pid, &status);
					change_stack(pid, stack_addr, stack_size, &orig);
					printf("changed stack position in memory layout\n");
					printf("stack_addr %lx\n", stack_addr);
					ptrace_cont(pid);
			waitpro(pid, &status);
					restore_orig(pid, &orig);
					setmems(pid, filePid, stack_addr);
					setregs(pid, filePid);
					ptrace_cont(pid);

		while(1){}
	return 0;
}

int target(char *path, char *argv[]){
	char *exec[] = {path, NULL};
	int ret;
	printf("CPID: %d\n", getpid());
	printf("command: %s\n", exec[0]);
	ptrace_traceme();
	printf("trace me\n");

	ret = execvp(exec[0], exec);
	perror("execvp");
	exit(ret);
}

/* Reference http://d.hatena.ne.jp/rti7743/20170616/1497628434 */

Elf64_Addr get_entry_point(char* filepath){
	int fd = open(filepath, O_RDONLY);
	if (fd < 0){
		return 0;
	}

	Elf_Ehdr ehdr;
	Elf_Shdr shdr;
	Elf_Shdr shdr_linksection;
	Elf_Sym  sym;
	int r = read(fd,&ehdr,sizeof(ehdr));
	if(r < 0){
		close(fd);
		return 0;
	}
	if(memcmp(ehdr.e_ident,ELFMAG,SELFMAG) != 0){
		close(fd);
		return 0;
	}

	for(int i = 0 ; i < ehdr.e_shnum ; i++ )
	{
		lseek(fd,ehdr.e_shoff + (i * sizeof(shdr)),SEEK_SET);
		r = read(fd,&shdr,sizeof(shdr));
		if ( r < sizeof(shdr)){
			continue;
		}
		if ( ! (shdr.sh_type == SHT_SYMTAB || shdr.sh_type == SHT_DYNSYM)){
			continue;
		}

		lseek(fd,ehdr.e_shoff + (shdr.sh_link * sizeof(shdr)),SEEK_SET);
		r = read(fd,&shdr_linksection,sizeof(shdr_linksection));
		if(r < sizeof(shdr_linksection)){
			continue;
		}

		const unsigned int nloop_count = shdr.sh_size / sizeof(sym);
		for(int n = 0 ; n < nloop_count; n++ ){
			lseek(fd,shdr.sh_offset + (n*sizeof(sym)),SEEK_SET);
			r = read(fd,&sym,sizeof(sym));
			if ( r < sizeof(sym) ){
				continue;
			}

			char buf[256];
			lseek(fd,shdr_linksection.sh_offset + sym.st_name,SEEK_SET);
			r = read(fd,buf,255);
			if ( r < 0 ){
				continue;
			}
			buf[r] = 0; 
			if(!strcmp(buf, "main")){
				printf("main address: 0x%lx\n", sym.st_value);
				return sym.st_value;
			}
		}
	}

	close(fd);
	return 0;
}

