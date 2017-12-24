#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <libprocstat.h>


int get_vmmap(int pid){
	struct procstat *prst;
	struct kinfo_vmentry *kve, *kv;
	struct kinfo_proc *kp;

	unsigned int count = 0;
	
	prst = procstat_open_sysctl();
	kp = procstat_getprocs(prst, KERN_PROC_PID, pid, &count);
	kve = procstat_getvmmap(prst, (void *)kp, &count);
	for(int i = 0; i < count; i++){
		kv = &kve[i];
		if(kv->kve_flags & KVME_FLAG_GROWS_DOWN){
			printf("start %d: %lx\n", i, kv->kve_start);
			printf("end %d: %lx\n", i, kv->kve_end);
		}
	}
	printf("stack text: %lx\n", kp->ki_tsize*4096);
	printf("stack data: %lx\n", kp->ki_dsize*4096);
	printf("stack size: %lx\n", kp->ki_ssize*4096);

	procstat_freevmmap(prst, (void *)kp);
	return 0;
	}
