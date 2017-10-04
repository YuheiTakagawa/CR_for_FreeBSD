#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#define BUFSIZE 1024 
int main(int argc, char* argv[]){
	pid_t pid;
	char mempath[30] = {'\0'};
	char dumppath[30] = {'\0'};
	char buf[BUFSIZE];
	int mem_fd, memdatadump_fd,memstackdump_fd;
	int rnum;
	int status;
	long int da, st;

	if(argc < 4){
		printf("Usage: %s <pid> <Data address> <Stack address>\n",argv[0]);
		exit(1);
	}

	pid = atoi(argv[1]);
	
	da = strtol(argv[2], NULL, 16);
	st = strtol(argv[3], NULL, 16);
	printf("da: %lx\n", da);
	printf("st: %lx\n", st);

	snprintf(mempath, 30, "/proc/%d/mem", pid);
	mem_fd = open(mempath, O_RDWR);
	if(mem_fd < 0){
		perror("open");
		exit(1);
	}

	snprintf(dumppath, 30, "/dump/%d_memdata.img", pid);
	memdatadump_fd = open(dumppath, O_WRONLY | O_CREAT);
	snprintf(dumppath, 30, "/dump/%d_memstack.img", pid);
	memstackdump_fd = open(dumppath, O_WRONLY | O_CREAT);
	if(memdatadump_fd < 0 || memstackdump_fd < 0){
		perror("open");
		exit(1);
	}


	if(ptrace(PT_ATTACH, pid, NULL, 0) < 0){
		perror("ptrace");
		exit (1);
	}

	waitpid(pid, &status, 0);
	if(WIFEXITED(status)){
			printf("exited");
			exit(1);
			}
	else if(WIFSTOPPED(status)){

	lseek(mem_fd, da, SEEK_SET);
	while(1){	
		rnum = read(mem_fd, buf, sizeof(buf));
		printf("%d\n", rnum);
		if(rnum > 0){
			write(memdatadump_fd, buf, rnum);
		}else{
			close(memdatadump_fd);
			printf("closed files\n");
			break;
		}
	}

	lseek(mem_fd, st, SEEK_SET);
	while(1){	
		rnum = read(mem_fd, buf, sizeof(buf));
		printf("%d\n", rnum);
		if(rnum > 0){
			write(memstackdump_fd, buf, rnum);
		}else{
			close(memstackdump_fd);
			printf("closed files\n");
			break;
		}
	}

	close(mem_fd);
	}
	if(ptrace(PT_DETACH, pid, NULL, 0) < 0){
		perror("ptrace");
		exit(1);
	}
	printf("detach\n");

	return 0;
}
