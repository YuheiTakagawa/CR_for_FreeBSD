#include <stdio.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <libprocstat.h>
//#include <kvm.h>
//#include <sys/user.h>

int main(int argc, char *argv[]){
	printf("hello world\n");

	int pid = atoi(argv[1]);
	struct procstat  *prst;
	struct filestat_list *fstlist;
	struct filestat *fst;
	struct kinfo_proc *kp;
	unsigned int mapped = 0;

	prst = procstat_open_sysctl();
	kp = procstat_getprocs(prst, KERN_PROC_PID, pid, &mapped);
	fstlist = procstat_getfiles(prst, (void *)kp, mapped);
	printf("filelist: %p\n", fstlist);
	STAILQ_FOREACH(fst, fstlist, next) {
		printf("FD: %d, OFFSET: %lx, PATH: %s\n", fst->fs_fd, fst->fs_offset, fst->fs_path);
	}
	
	procstat_freeprocs(prst, (void *)kp);
	return 0;
}
