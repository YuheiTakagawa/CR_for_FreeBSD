#ifndef GETFD
#define GETFD

#include <stdio.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <dirent.h>

#include "files.h"

#define FD_MAX 1024
#define BUF_SIZE 1024
#define PATH_BUF 1024

struct fd_list{
	int fd[FD_MAX];
	char path[PATH_BUF][FD_MAX];
	unsigned long int offset[FD_MAX];
};

/* Get FD position(file offset) from /proc/PID/fdinfo */
unsigned long int get_fd_pos(pid_t pid, int fd){
	char path[PATH_BUF];
	char buf[BUF_SIZE];
	FILE *fp;
	unsigned long int pos = 0;

	snprintf(path, PATH_BUF, "/proc/%d/fdinfo/%d", pid, fd);
	fp = fopen(path, "r");
	while(fgets(buf, BUF_SIZE, fp) != NULL){
		if(!strncmp(buf, "pos:", sizeof("pos"))){
			sscanf(buf, "%*s %ld", &pos);
		}
	}
	return pos;
}

/* Get actual FD path name, not symbolic link */
int get_fd_path(pid_t pid, int fd, char *fd_path){
	int size;
	char link[PATH_BUF], path[PATH_BUF];

	snprintf(path, PATH_BUF, "/proc/%d/fd/%d", pid, fd);
	size = readlink(path, link, sizeof(link));
	link[size] = 0;
	strncpy(fd_path, link, sizeof(link));

	return size;
}

/* Get fd infomation fd number, path, offset */
/* This implement is used array however not increment */

int *get_open_fd(pid_t pid, struct fd_list *fdl){

	char path[PATH_BUF] = {'\0'};
	struct dirent *de;
	DIR *fd_dir;
	int i = 0;
	snprintf(path, PATH_BUF, "/proc/%d/fd", pid);

	fd_dir = opendir(path);
	if(!fd_dir){
		perror("opendir");
	} 

	while((de = readdir(fd_dir))){
		if(atoi(de->d_name) > 2){
			fdl->fd[i] = atoi(de->d_name);
			get_fd_path(pid, fdl->fd[i], fdl->path[i]);
			fdl->offset[i] = get_fd_pos(pid, fdl->fd[i]);
			i++;
		}
	}
	return 0;
}

int getfd(pid_t pid){
	struct fd_list fdl;
	get_open_fd(pid, &fdl);
	for(int i = 0; i < FD_MAX; i++){
		if(fdl.fd[i] != 0){
		printf("FD: %d, OFFSET: %lx, PATH: %s\n", fdl.fd[i], fdl.offset[i], fdl.path[i]);
		}
		else{ break; }
	}

	printf("finished get fd\n");
	return 0;
}

#endif
