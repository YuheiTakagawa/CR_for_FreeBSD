#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#define BUFSIZE 1024 
#define PATHBUF 30

int open_read_file(pid_t pid);
int tracing(pid_t pid, long int daoffset, long int stoffset);
int getmem(int read_fd, int dump_fd, long int offset);

int open_read_file(pid_t pid){
	int fd;
	char filepath[PATHBUF] = {'\0'};
	
	snprintf(filepath, sizeof(filepath), "/proc/%d/mem", pid);
	fd = open(filepath, O_RDONLY);
	if(fd < 0){
		perror("open");
		exit(1);
	}

	return fd;
}

int open_dump_file(pid_t pid, char *dumptype){
	int fd;
	char filepath[PATHBUF] = {'\0'};

	snprintf(filepath, sizeof(filepath) , "/dump/%d_%s.img", pid, dumptype);
	fd = open(filepath, O_WRONLY | O_CREAT);
	if(fd < 0){
		perror("open");
		exit(1);
	}

	return fd;
}

int getmems(pid_t pid, long int dataoffset, long int stackoffset){
	int read_fd, dump_fd;
	
	read_fd = open_read_file(pid);
	
	dump_fd = open_dump_file(pid, "data");
	getmem(read_fd, dump_fd, dataoffset);

	dump_fd = open_dump_file(pid, "stack");
	getmem(read_fd, dump_fd, stackoffset);

	close(read_fd);
	return 0;
}



int getmem(int read_fd, int dump_fd, long int offset){
	char buf[BUFSIZE];
	int rnum;
	
	lseek(read_fd, offset, SEEK_SET);

	while(1){	

		rnum = read(read_fd, buf, sizeof(buf));
//		printf("%d\n", rnum);

		if(rnum > 0){
		
			write(dump_fd, buf, rnum);
		
		}else{
		
			close(dump_fd);
			printf("closed files\n");
			break;
		
		}
	}

	return 0;
}
