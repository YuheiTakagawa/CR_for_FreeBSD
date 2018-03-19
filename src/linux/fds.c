#include <stdio.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <dirent.h>

#include "files.h"

#include "common.h"
#include "fds.h"

int prepare_restore_files(char *path, int fd, off_t foff){
        printf("PATH:%s\n", path);
        int tmp = open(path, O_RDWR);
        if(fd != tmp){
                fd = dup2(tmp, fd);
                close(tmp);
        }
        lseek(fd, foff, SEEK_SET);
        return fd;
}

void read_fd_list(pid_t filePid, struct restore_fd_struct *fds){
        int read_fd;
        char buf[BUFSIZE];
        int i = 0;
        read_fd = open_file(filePid, "fds");
        while(read(read_fd, &buf[i++], sizeof(char))){
                if(buf[i-1] == '\n'){
                        buf[i-1] = '\0';
                        fds->fd = atoi(strtok(buf, ","));
                        fds->offset = strtol(strtok(NULL, ","), NULL, 16);
                        strncpy(fds->path, strtok(NULL, "\0"), i);
                        fds++;
                        i = 0;
                }
        }
        close(read_fd);
}


/* Get FD position(file offset) from /proc/PID/fdinfo */
static unsigned long int get_fd_pos(pid_t pid, int fd){
	char path[PATHBUF];
	char buf[BUFSIZE];
	FILE *fp;
	unsigned long int pos = 0;

	snprintf(path, PATHBUF, "/proc/%d/fdinfo/%d", pid, fd);
	fp = fopen(path, "r");
	while(fgets(buf, BUFSIZE, fp) != NULL){
		if(!strncmp(buf, "pos:", sizeof("pos"))){
			sscanf(buf, "%*s %ld", &pos);
		}
	}
	return pos;
}

/* Get actual FD path name, not symbolic link */
static int get_fd_path(pid_t pid, int fd, char *fd_path){
	int size;
	char link[PATHBUF], path[PATHBUF];

	snprintf(path, PATHBUF, "/proc/%d/fd/%d", pid, fd);
	size = readlink(path, link, sizeof(link));
	link[size] = 0;
	strncpy(fd_path, link, sizeof(link));

	return size;
}

/* Get fd infomation fd number, path, offset */
/* This implement is used array however not increment */

int *get_open_fd(pid_t pid, struct fd_list *fdl){

	char path[PATHBUF] = {'\0'};
	struct dirent *de;
	DIR *fd_dir;
	int i = 0;
	snprintf(path, PATHBUF, "/proc/%d/fdinfo", pid);

	fd_dir = opendir(path);
	if(!fd_dir){
		perror("opendir");
	} 
	while((de = readdir(fd_dir))){
		if(atoi(de->d_name) > 0){
			fdl->fd[i] = atoi(de->d_name);
			get_fd_path(pid, fdl->fd[i], fdl->path[i]);
			fdl->offset[i] = get_fd_pos(pid, fdl->fd[i]);
			i++;
		}
	}
	fdl->fd[i] = -2;
	return 0;
}

int getfd(pid_t pid){
	struct fd_list fdl;
	get_open_fd(pid, &fdl);
	int write_fd = open_dump_file(pid, "fds");
	for(int i = 0; i < FD_MAX; i++){
		if(fdl.fd[i] >= 0){
			printf("FD: %d, OFFSET: %lx, PATH: %s\n", fdl.fd[i], fdl.offset[i], fdl.path[i]);
			dprintf(write_fd, "%d,%lx,%s\n", fdl.fd[i], fdl.offset[i], fdl.path[i]);
		}
		if(fdl.fd[i] == -2){
			dprintf(write_fd, "%d,%x,%s\n", -2, -1, " ");
			break;
		}
	}

	printf("finished get fd\n");
	return 0;
}
