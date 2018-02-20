#ifndef __COMPEL_INFECT_H__
#define __COMPEL_INFECT_H__

struct parasite_ctl;

#define compel_parasite_args(ctl, type)	\
	({	\
	 void *___ret;	\
	 ___ret = compel_parasite_args_p(ctl);	\
	 ___ret;	\
	 })

extern void *compel_parasite_args_p(struct parasite_ctl *ctl);



typedef int (*open_proc_fn)(int pid, int mode, const char *fmt, ...)
	__attribute__ ((__format__ (__printf__, 3, 4)));

struct infect_ctx {
	int	sock;

	/*
	 * Regs manipulation context.
	 */
	//int (*save_regs)(void *, user_regs_struct_t *, user_fpregs_struct_t *);
	//int (*make_sigframe)(void *, struct rt_sigframe *, struct rt_sigframe *, k_rtsigset_t *);
	void *regs_arg;

	unsigned long		task_size;
	unsigned long		syscall_ip;				/* entry point of infection */
	unsigned long		flags;			/* fine-tune (e.g. faults) */

	//void (*child_handler)(int, siginfo_t *, void *);	/* hander for SIGCHLD deaths */
	//struct sigaction	orig_handler;

	open_proc_fn open_proc;

	int			log_fd;	/* fd for parasite code to send messages to */
};


#define INFECT_FAIL_CONNECT 0x2

#endif
