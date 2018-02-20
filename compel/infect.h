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

#endif
