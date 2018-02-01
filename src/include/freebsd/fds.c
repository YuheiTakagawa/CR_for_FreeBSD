#ifndef GETFD
#define GETFD

#include <stdio.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <libprocstat.h>

#include "files.h"

#define FD_MAX 1024

struct restore_fd_struct{
	char path[BUFSIZE];
	int fd;
	off_t offset;
};

struct fd_list{
	int fd[FD_MAX];
	char *path[FD_MAX];
	off_t offset[FD_MAX];
};

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

int *get_open_fd(int pid, struct fd_list *fdl){

	struct procstat  *prst;
	struct filestat_list *fstlist;
	struct filestat *fst;
	struct kinfo_proc *kp;
	unsigned int mapped = 0;

	int i = 0;
	sync();
	// get struct procstat
	prst = procstat_open_sysctl();
	// get kinfo_proc with pid
	kp = procstat_getprocs(prst, KERN_PROC_PID, pid, &mapped);
	// get pid process has file list
	fstlist = procstat_getfiles(prst, (void *)kp, mapped);
	// separate file list
	STAILQ_FOREACH(fst, fstlist, next) {
			fdl->fd[i] = fst->fs_fd;
			fdl->path[i] = fst->fs_path;
			fdl->offset[i] = fst->fs_offset;
			i++;
	}
	fdl->fd[i] = -2;
	
	procstat_freeprocs(prst, (void *)kp);
	return 0;
}

int getfd(int pid){
	struct fd_list fdl;
	get_open_fd(pid, &fdl);
	int write_fd = open_dump_file(pid, "fds");
	for(int i = 0; i < FD_MAX; i++){
		/* file descriptor is range -1 ~, error code is -2 */
		if(fdl.fd[i] > 0){
			printf("FD: %d, OFFSET: %lx, PATH: %s\n", fdl.fd[i], fdl.offset[i], fdl.path[i]);
			dprintf(write_fd, "%d,%lx,%s\n", fdl.fd[i], fdl.offset[i], fdl.path[i]);
		}
		if(fdl.fd[i] == -2){
			dprintf(write_fd, "%d,%lx,%s\n", -2, -1, NULL);
		       	break;
	       	}
	}

	printf("finished get fd\n");
	return 0;
}

#endif
