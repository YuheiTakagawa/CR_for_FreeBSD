#ifndef __COMPEL_INFECT_PRIV_H__
#define __COMPEL_INFECT_PRIV_H__

#include <stdbool.h>

struct parasite_ctl{
	int rpid;
	void *remote_map;
	void *local_map;
	void *sigreturn_addr;
	unsigned long map_length;

	struct infect_ctx ictx;
	
	bool daemonized;

	//struct thread_ctx orig;

	void *rstack;
	//struct rt_sigframe *sigframe;
	//struct rt_sigframe *rsigframe;

	void *r_thread_stack;

	unsigned int *addr_cmd;
	void *addr_args;
	unsigned long args_size;
	int tsock;

	//struct parasite_blob_desc pblob;
};
	
struct ctl_msg;
int parasite_wait_ack(int sockfd, unsigned int cmd, struct ctl_msg *m);
#endif
