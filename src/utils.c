#define _XOPEN_SOURCE

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <limits.h>
#include <signal.h>
#include <unistd.h>

#include "servicefd.h"

static int service_fd_base;
static int service_fd_id = 0;

static int __get_service_fd(enum sfd_type type, int service_fd_id) {
	return service_fd_base - type - SERVICE_FD_MAX * service_fd_id;
}

int get_service_fd(enum sfd_type type) {
	return __get_service_fd(type, service_fd_id);
}
