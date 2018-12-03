#ifndef __CR_SERVICE_FD_H__
#define __CR_SERVICE_FD_H__

#include <stdbool.h>

enum sfd_type {
	SERVICE_FD_MIN,

	LOG_FD_OFF,
	IMG_FD_OFF,
	PROC_FD_OFF,
	PROC_PID_FD_OFF,
	CR_PROC_FD_OFF,
	ROOT_FD_OFF,
	CGROUP_YARD,
	USERNSD_SK,
	NS_FD_OFF,
	TRANSPORT_FD_OFF,
	RPC_SK_OFF,
	FDSTORE_SK_OFF,
	SERVICE_FD_MAX
};

struct pstree_item;
extern bool sfds_protected;

extern void set_proc_self_fd(int fd);
extern int clone_service_fd(struct pstree_item *me);
extern int init_service_fd(void);
extern int get_service_fd(enum sfd_type type);
extern int install_service_fd(enum sfd_type type, int fd);
extern int close_service_fd(enum sfd_type type);
extern bool is_service_fd(int fd, enum sfd_type type);
extern bool is_any_service_fd(int fd);
extern int service_fd_min_fd(struct pstree_item *);
#endif
