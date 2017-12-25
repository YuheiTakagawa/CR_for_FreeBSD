#ifndef GETMEM
#define GETMEM

#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include "files.h"

#define BUFSIZE 1024 
#define PATHBUF 30

int getmem(int read_fd, int dump_fd, long int offset);

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
	unsigned long int sum = 0x0;
	
	lseek(read_fd, offset, SEEK_SET);

	while(1){	

		rnum = read(read_fd, buf, sizeof(buf));
		sum += rnum;
//		printf("%d\n", rnum);

		if(sum <= 0x21000 || rnum > 0){
		
			write(dump_fd, buf, rnum);
		
		}else{
		
			close(dump_fd);
			printf("closed files\n");
			break;
		
		}
	}

	return 0;
}

#endif
