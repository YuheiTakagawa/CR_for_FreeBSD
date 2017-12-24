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
#include "getmap.c"

#define BUFSIZE 1024 
#define PATHBUF 30

int getmem(int read_fd, int dump_fd, long int offset, long int size);

int getmems(pid_t pid, long int dataoffset, long int stackoffset){
	int read_fd, dump_fd;
	struct vmds vmds;
	get_vmmap(pid, &vmds);
	read_fd = open_read_file(pid);
	
	dump_fd = open_dump_file(pid, "data");
	//getmem(read_fd, dump_fd, dataoffset, vmds.dsize); //If don't use argument dataoffset, please, remove
	getmem(read_fd, dump_fd, vmds.daddr, vmds.dsize);

	dump_fd = open_dump_file(pid, "stack");
	//getmem(read_fd, dump_fd, stackoffset, vmds.ssize); //If don't use argument stackoffset, please remove
	getmem(read_fd, dump_fd, vmds.saddr, vmds.ssize);

	close(read_fd);
	return 0;
}



int getmem(int read_fd, int dump_fd, long int offset, long int size){
	char buf[BUFSIZE];
	int rnum;
	unsigned long int sum = 0x0;
	
	lseek(read_fd, offset, SEEK_SET);

	while(1){	

		rnum = read(read_fd, buf, sizeof(buf));
		sum += rnum;

		if(sum <= size){
		
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
