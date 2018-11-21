#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include "cr-service.h"

void* xmalloc(size_t size) {
	void *p = malloc(size);
	if (p == NULL) {
		printf("Out of memory\n");
		exit(1);
	}
	return p;
}

static int recv_criu_msg(int socket_fd, CriuReq **req) {
	unsigned char *buf;
	int len;

	len = recv(socket_fd, NULL, 0, MSG_TRUNC | MSG_PEEK);
	ioctl(socket_fd, FIONREAD, &len);
	if (len == -1) {
		printf("Can't read request");
		return -1;
	}

	printf("size %d\n", len);

	buf = xmalloc(len);
	if (!buf)
		return -ENOMEM;

	len = recv(socket_fd, buf, len, MSG_TRUNC);
	if (len == -1) {
		printf("Can't read request");
		goto err;
	}

	if (len == 0) {
		printf("Client exited unexpectedly\n");
		errno = ECONNRESET;
		goto err;
	}

	*req = criu_req__unpack(NULL, len, buf);
	if (!*req) {
		printf("Failed unpacking request");
		goto err;
	}

	free(buf);
	return 0;
err:
	free(buf);
	return -1;
}


int cr_service_work(int sk) {
	int ret = -1;
	CriuReq *msg = 0;

more:
	if (recv_criu_msg(sk, &msg) == -1) {
		printf("Can't recv request");
		goto err;
	}

	printf("msgtype %d\n", msg->type);
	return 0;

err:
	return ret;
}
