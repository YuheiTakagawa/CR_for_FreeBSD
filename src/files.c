#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include "common.h"


int open_file(pid_t pid, char* flag){
	char filepath[PATHBUF];

	if(!strcmp(flag, "mem")){
	snprintf(filepath, sizeof(filepath), "/proc/%d/mem", pid);
	return  open(filepath, O_WRONLY);
	}
	snprintf(filepath, sizeof(filepath), "/dump/%d_%s.img", pid, flag);
	return open(filepath, O_RDONLY);
}

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

	snprintf(filepath, sizeof(filepath), "/dump/%d_%s.img", pid, dumptype);
	fd = open(filepath, O_WRONLY | O_CREAT);
	if(fd < 0){
		perror("open");
		exit(1);
	}

	return fd;
}

