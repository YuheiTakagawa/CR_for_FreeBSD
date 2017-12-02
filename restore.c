#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>

#define BUFSIZE 1024
#define PATHBUF 30

int target(char *path, char* argv[]);
int setmems(pid_t pid, pid_t filePid);
int write_mem(int read_fd, int write_fd, long int offset);
int setregs(pid_t pid, pid_t filePid);
int open_file(pid_t pid, char* st);
Elf64_Addr get_entry_point(char* filepath);

struct linuxreg {
  unsigned long int r15;
  unsigned long int r14;
  unsigned long int r13;
  unsigned long int r12;
  unsigned long int rbp;
  unsigned long int rbx;
  unsigned long int r11;
  unsigned long int r10;
  unsigned long int r9;
  unsigned long int r8;
  unsigned long int rax;
  unsigned long int rcx;
  unsigned long int rdx;
  unsigned long int rsi;
  unsigned long int rdi;
  unsigned long int orig_rax;
  unsigned long int rip;
  unsigned long int cs;
  unsigned long int eflags;
  unsigned long int rsp;
  unsigned long int ss;
  unsigned long int fs_base;
  unsigned long int gs_base;
  unsigned long int ds;
  unsigned long int es;
  unsigned long int fs;
  unsigned long int gs;
};

int main(int argc, char* argv[]){
	int pid, filePid;
	int status;
	int flag = 0;
	char *filepath;
	long origin_text;
	Elf64_Addr entry_point;

	if(argc < 3){
		printf("Usage: %s <path> <file pid>\n", argv[0]);
		exit(1);
	}
	filepath = argv[1];
	filePid = atoi(argv[2]);
	printf("CMD : %s\n", argv[1]);
	printf("PPID: %d\n", getpid());
	printf("Restore file: %d\n", filePid); 

	pid = fork();
	if(pid < 0){
		perror("FORK");
		exit(1);
	}
	
	if(pid == 0){
		target(filepath, NULL);
	}else{
		while(1){
			if(waitpid(pid, &status, 0) < 0){
				perror("waitpid");
				exit(1);
			}
			if(WIFSTOPPED(status)){
				if(flag == 0){
				//	entry_point = get_entry_point(filepath);
					entry_point = 0x4009ae;
					origin_text = ptrace(PT_READ_I, pid, (caddr_t)entry_point, 0);
					ptrace(PT_WRITE_I, pid, (caddr_t)entry_point, 0xCC);
					ptrace(PT_CONTINUE, pid, (caddr_t)1, 0);
					flag++;
				}
				else{
					printf("stopped:%d\n", WSTOPSIG(status));
					setmems(pid, filePid);
					ptrace(PT_WRITE_I, pid, (caddr_t)entry_point, origin_text);
					setregs(pid, filePid);
					printf("finished setting values\n");
					ptrace(PT_CONTINUE, pid, (caddr_t)1, 0);
				}
			}else if(WIFEXITED(status)){
				perror("exited");
				exit(1);
			}
		}
	}
	return 0;
}

int target(char *path, char *argv[]){
	char *exec[] = {path, NULL};
	int ret;
	printf("CPID: %d\n", getpid());
	printf("command: %s\n", exec[0]);
	ptrace(PT_TRACE_ME, 0, NULL, 0);
	printf("trace me\n");
	
	ret = execvp(exec[0], exec);
	perror("execvp");
	exit(ret);
}

int setregs(int pid, pid_t filePid){
	struct reg reg;
	struct linuxreg linuxreg;
	int fd;

	memset(&reg, 0, sizeof(reg));
	fd = open_file(filePid, "regs");
	read(fd, &linuxreg, sizeof(linuxreg));

	ptrace(PT_GETREGS, pid, (caddr_t)&reg, 0);

	reg.r_rax=linuxreg.orig_rax;
	reg.r_rbx=linuxreg.rbx;
	reg.r_rcx=linuxreg.rcx;
	reg.r_rdx=linuxreg.rdx;
	reg.r_rsi=linuxreg.rsi;
	reg.r_rdi=linuxreg.rdi;
	reg.r_rbp=linuxreg.rbp;
	reg.r_rsp=linuxreg.rsp;
	reg.r_rip=linuxreg.rip;
	reg.r_rflags=linuxreg.eflags;
	reg.r_r8=linuxreg.r8;
	reg.r_r9=linuxreg.r9;
	reg.r_r10=linuxreg.r10;
	reg.r_r11=linuxreg.r11;
	reg.r_r12=linuxreg.r12;
	reg.r_r13=linuxreg.r13;
	reg.r_r14=linuxreg.r14;
	reg.r_r15=linuxreg.r15;

/*	reg.r_cs=0x43;
	reg.r_ss=0x3b;
	reg.r_ds=0x0;
	reg.r_es=0x0;
	reg.r_fs=0x0;
	reg.r_gs=0x0;
*/	
	if(ptrace(PT_SETREGS, pid, (caddr_t)&reg, 0) < 0){
		perror("ptrace(PT_SETREGS, ...)");
		exit(1);
	}
	return 0;
}

int setmems(pid_t pid, pid_t filePid){
	int write_fd;
	int read_fd;
	char buf[BUFSIZE];

	write_fd = open_file(pid, "mem");
	

	read_fd = open_file(filePid, "data");
	write_mem(read_fd, write_fd, 0x6c9000);	

	read_fd = open_file(filePid, "stack");
	write_mem(read_fd, write_fd, 0x7ffffffdf000);

	close(write_fd);
	return 0;
}

int open_file(pid_t pid, char* flag){
	char filepath[PATHBUF];

	if(flag == "mem"){
		snprintf(filepath, sizeof(filepath), "/proc/%d/mem", pid);
		return  open(filepath, O_WRONLY);
	}	
	snprintf(filepath, sizeof(filepath), "/dump/%d_%s.img", pid, flag);
	return open(filepath, O_RDONLY);
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

Elf64_Addr get_entry_point(char* filepath){
		Elf64_Ehdr header;
		int fd = open(filepath, O_RDONLY);
		memset(&header, 0, sizeof(Elf64_Ehdr));

		read(fd, &header, sizeof(header));
		Elf64_Addr entry = header.e_entry;
		return entry;
}
