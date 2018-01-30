#ifndef __GET_VM_
#define __GET_VM_

#include <stdio.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <libprocstat.h>

#include "files.h"

#define SHOW_VMMAP 0
#define DUMP_VMMAP 1

struct vmds{
	unsigned long int dsize;
	unsigned long int ssize;
	unsigned long int daddr;
	unsigned long int saddr;
};

void get_vmmap(int pid, struct vmds *vmds, int flag){
	struct procstat *prst;
	struct kinfo_proc *kp;
	struct kinfo_vmentry *kve, *kv;
	unsigned int count = 0;
	char tmp[BUFSIZE];

	int page_size;
	int size;

	int write_fd = open_dump_file(pid, "map");

	page_size = getpagesize();

	prst = procstat_open_sysctl();
	kp = procstat_getprocs(prst, KERN_PROC_PID, pid, &count);

	kve = procstat_getvmmap(prst, (void *)kp, &count);

	for(int i = 0; i < count; i++){
		kv = &kve[i];
		printf("begin: %lx, end: %lx, flag: %x, prot: %x, path: %s, off: %lx\n", kv->kve_start, kv->kve_end, kv->kve_flags, kv->kve_protection, kv->kve_path, kv->kve_offset);
		if(flag == DUMP_VMMAP){
			char *buf = kv->kve_path;
			if(strlen(buf) == 0)
				buf = " ";
			size = snprintf(tmp, sizeof(tmp), "%lx,%lx,%x,%x,%s,%lx\n", kv->kve_start, kv->kve_end, kv->kve_flags, kv->kve_protection, buf, kv->kve_offset);
			write(write_fd, tmp, size);
		}
		if(i == 1){
			vmds->daddr = kv->kve_start;
			continue;
		}

		if(kv->kve_flags & KVME_FLAG_GROWS_DOWN){
			vmds->saddr = kv->kve_start;
			continue;
		}
		
	}
	/************************************************/
	vmds->dsize = kp->ki_dsize * page_size;
	vmds->ssize = kp->ki_ssize * page_size;

	printf("stack text: %lx\n", kp->ki_tsize * page_size);
	printf("stack data: %lx\n", vmds->dsize);
	printf("stack size: %lx\n", vmds->ssize);

	procstat_freevmmap(prst, (void *)kp);
}

void show_vmmap(pid_t pid, struct vmds *vmds){
	get_vmmap(pid, vmds, SHOW_VMMAP);
}

void dump_vmmap(pid_t pid, struct vmds *vmds){
	get_vmmap(pid, vmds, DUMP_VMMAP);
}

#endif
