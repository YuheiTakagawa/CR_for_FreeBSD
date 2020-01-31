#define _XOPEN_SOURCE

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <limits.h>
#include <signal.h>
#include <unistd.h>

#include "xmalloc.h"
#include "vma.h"
#include "servicefd.h"
#include "log.h"

static int service_fd_base;
static int service_fd_id = 0;

static int __get_service_fd(enum sfd_type type, int service_fd_id) {
	return service_fd_base - type - SERVICE_FD_MAX * service_fd_id;
}

int get_service_fd(enum sfd_type type) {
	return __get_service_fd(type, service_fd_id);
}

int close_safe(int *fd)
{
	int ret = 0;

	if (*fd > -1) {
		ret = close(*fd);
		if (!ret)
			*fd = -1;
		else
			pr_perror("Unable to close fd %d", *fd);
	}

	return ret;
}

int read_fd_link(int lfd, char *buf, size_t size)
{
	char t[32];
	ssize_t ret;

	snprintf(t, sizeof(t), "/proc/self/fd/%d", lfd);
	ret = readlink(t, buf, size);
	if (ret < 0) {
		pr_perror("Can't read link of fd %d", lfd);
		return -1;
	} else if ((size_t)ret >= size) {
		pr_err("Buffer for read link of fd %d is too small\n", lfd);
		return -1;
	}
	buf[ret] = 0;

	return ret;
}

struct vma_area *alloc_vma_area(void)
{
	struct vma_area *p;

	p = xzalloc(sizeof(*p) + sizeof(VmaEntry));
	if (p) {
		p->e = (VmaEntry *)(p + 1);
		vma_entry__init(p->e);
		p->e->fd = -1;
	}

	return p;
}
