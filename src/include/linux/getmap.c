#ifndef __GET_VM_
#define __GET_VM_

#include <unistd.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/user.h>
//#include <libprocstat.h>

struct vmds{
	unsigned long int dsize;
	unsigned long int ssize;
	unsigned long int daddr;
	unsigned long int saddr;
};

void get_vmmap(int pid, struct vmds* vmds){
/*	
	struct procstat *prst;
	struct kinfo_proc *kp;
	struct kinfo_vmentry *kve, *kv;

	unsigned int count = 0;
	int page_size;

	page_size = getpagesize();

	prst = procstat_open_sysctl();
	kp = procstat_getprocs(prst, KERN_PROC_PID, pid, &count);
	kve = procstat_getvmmap(prst, (void *)kp, &count);
	for(int i = 0; i < count; i++){
		kv = &kve[i];
		if(i == 1){
			vmds->daddr = kv->kve_start;
			continue;
		}

		if(kv->kve_flags & KVME_FLAG_GROWS_DOWN){
			vmds->saddr = kv->kve_start;
			continue;
		}
	}
*/
	vmds->dsize = 0x28000;
	vmds->ssize = 0x21000;
	vmds->daddr = 0x6c9000;
	vmds->saddr = 0x7ffffffde000;

	printf("stack data: %lx\n", vmds->dsize);
	printf("stack size: %lx\n", vmds->ssize);

//	procstat_freevmmap(prst, (void *)kp);
}

#endif
