#ifndef GETFD
#define GETFD

#include <stdio.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
//#include <libprocstat.h>

#include "files.h"

#define FD_MAX 1024

struct fd_list{
	int fd[FD_MAX];
	char *path[FD_MAX];
	unsigned long int offset[FD_MAX];
};

int *get_open_fd(int pid, struct fd_list *fdl){
/*
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
		if(fst->fs_fd > 2){
			fdl->fd[i] = fst->fs_fd;
			fdl->path[i] = fst->fs_path;
			fdl->offset[i] = fst->fs_offset;
			i++;
		}
	}
	
	procstat_freeprocs(prst, (void *)kp);
*/	fdl->fd[0] = 32;
	fdl->path[0] = "/dump/hello";
	fdl->offset[0] = 400;
	return 0;
}

int getfd(int pid){
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
