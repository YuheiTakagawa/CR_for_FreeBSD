#ifndef __COMMON_SCM_H__
#define __COMMON_SCM_H__

#include <stdint.h>
#include <stdbool.h>
#include <sys/un.h>

#define CR_SCM_MSG_SIZE (1024)
#define CR_SCM_MAX_FD (252)

struct scm_fdset {
	struct msghdr	hdr;
	struct iovec	iov;
	char		msg_buf[CR_SCM_MSG_SIZE];
};

extern int send_fds(int sock, struct sockaddr_un *saddr, int len,
		int *fds, int nr_fds, void *data, unsigned ch_size);
extern int __recv_fds(int sock, int *fds, int nr_fds,
		void *data, unsigned ch_size, int flags);
static inline int recv_fds(int sock, int *fds, int nr_fds,
		void *data, unsigned ch_size){
	return __recv_fds(sock, fds, nr_fds, data, ch_size, 0);
}

static inline int send_fd(int sock, struct sockaddr_un *saddr, int saddr_len, int fd) {
	return send_fds(sock, saddr, saddr_len, &fd, 1, NULL, 0);
}

static inline int recv_fd(int sock) {
	int fd, ret;

	ret = recv_fds(sock, &fd, 1, NULL, 0);
	if (ret)
		return -1;
	return fd;
}

#endif