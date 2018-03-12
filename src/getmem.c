#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include "files.h"
#include "getmap.h"

#include "getmem.h"
#include "common.h"

int getmems(pid_t pid){
	int read_fd, dump_fd;
	struct vmds vmds;
	dump_vmmap(pid, &vmds);
	read_fd = open_read_file(pid);
	
	dump_fd = open_dump_file(pid, "heap");
	getmem(read_fd, dump_fd, vmds.haddr, vmds.hsize);


	dump_fd = open_dump_file(pid, "stack");
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

