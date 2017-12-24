#ifndef __GET_VM_
#define __GET_VM_

#include <unistd.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <libprocstat.h>

struct vmsize{
	unsigned long int data;
	unsigned long int stack;
};

void get_vmmap(int pid, struct vmsize* size){
	struct procstat *prst;
	struct kinfo_proc *kp;

	unsigned int count = 0;
	int page_size;
	page_size = getpagesize();

	prst = procstat_open_sysctl();
	kp = procstat_getprocs(prst, KERN_PROC_PID, pid, &count);
	/* Please remove commentout, if you want to get stack offset */
	/*
	struct kinfo_vmentry *kve, *kv;
	kve = procstat_getvmmap(prst, (void *)kp, &count);
	for(int i = 0; i < count; i++){
		kv = &kve[i];
		if(kv->kve_flags & KVME_FLAG_GROWS_DOWN){
			printf("start %d: %lx\n", i, kv->kve_start);
			printf("end %d: %lx\n", i, kv->kve_end);
		}
	}
	*/
	size->data = kp->ki_dsize * page_size;
	size->stack = kp->ki_ssize * page_size;

	printf("stack text: %lx\n", kp->ki_tsize * page_size);
	printf("stack data: %lx\n", size->data);
	printf("stack size: %lx\n", size->stack);

	procstat_freevmmap(prst, (void *)kp);
}

#endif
