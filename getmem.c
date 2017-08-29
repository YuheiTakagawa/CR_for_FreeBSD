#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

int main(int argc, char* argv[]){
	pid_t pid;
	char mempath[30] = {'\0'};
	char dumppath[30] = {'\0'};
	char buf[128];
	int mem_fd, memdump_fd;
	int rnum;
	
	if(argc < 2){
		printf("Usage: %s <pid>\n", argv[0]);
		exit(1);
	}

	pid = atoi(argv[1]);


	snprintf(mempath, 30, "/proc/%d/mem", pid);
	mem_fd = open(mempath, O_RDWR);
	if(mem_fd < 0){
		perror("open");
		exit(1);
	}

	snprintf(dumppath, 30, "/dump/%d_mem.img", pid);
	memdump_fd = open(dumppath, O_WRONLY | O_CREAT);
	if(memdump_fd < 0){
		perror("open");
		exit(1);
	}


	ptrace(PT_ATTACH, pid, NULL, 0);
	waitpid(pid, NULL, 0);
	lseek(mem_fd, 0x400000, SEEK_SET);
	
	while(1){
		rnum = read(mem_fd, buf, sizeof(buf));
		if(rnum > 0){
			write(memdump_fd, buf, rnum);
		}else if(rnum == 0){
			close(mem_fd);
			close(memdump_fd);
			break;
		}else{
			perror("read");
			return -1;
		}
	}
	ptrace(PT_CONTINUE, pid, NULL, 0);


	return 0;
}
