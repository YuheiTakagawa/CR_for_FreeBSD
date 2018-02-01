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

struct fd_list{
	int fd[FD_MAX];
	char *path[FD_MAX];
	unsigned long int offset[FD_MAX];
};

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
