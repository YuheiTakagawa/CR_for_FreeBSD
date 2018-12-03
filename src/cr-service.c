#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include "scm.h"
#include "crtools.h"
#include "cr-service.h"
#include "criu-log.h"
#include "cr-errno.h"

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

	recv(socket_fd, NULL, 0, MSG_PEEK);
	ioctl(socket_fd, FIONREAD, &len);
	if (len == -1) {
		printf("Can't read request");
		return -1;
	}
	
	printf("size %d\n", len);

	buf = xmalloc(len);
	if (!buf)
		return -ENOMEM;

	len = recv(socket_fd, buf, len, MSG_PEEK);
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

static int send_criu_msg_with_fd(int socket_fd, CriuResp *msg, int fd) {
	unsigned char *buf;
	int len, ret;

	len = criu_resp__get_packed_size(msg);

	buf = xmalloc(len);
	if (!buf)
		return -ENOMEM;

	if (criu_resp__pack(msg, buf) != len) {
		pr_perror("Failed packing response");
		goto err;
	}

	if (fd >= 0) {
		ret = send_fds(socket_fd, NULL, 0, &fd, 1, buf, len);
	} else
		ret = write(socket_fd, buf, len);
	if (ret < 0) {
		pr_perror("Can't send response");
		goto err;
	}

	free(buf);
	return 0;
err:
	free(buf);
	return -1;
}

static int send_criu_msg(int socket_fd, CriuResp *msg) {
	return send_criu_msg_with_fd(socket_fd, msg, -1);
}

static void set_resp_err(CriuResp *resp) {
	resp->cr_errno = get_cr_errno();
	resp->has_cr_errno = resp->cr_errno ? true : false;
	resp->cr_errmsg = log_first_err();
}

static void send_criu_err(int sk, char *msg) {
	CriuResp resp = CRIU_RESP__INIT;

	pr_perror("RPC error: %s", msg);
	resp.type = CRIU_REQ_TYPE__EMPTY;
	resp.success = false;
	set_resp_err(&resp);

	send_criu_msg(sk, &resp);
}

int send_criu_dump_resp(int socket_fd, bool success, bool restored) {
	CriuResp msg = CRIU_RESP__INIT;
	CriuDumpResp resp = CRIU_DUMP_RESP__INIT;

	msg.type = CRIU_REQ_TYPE__DUMP;
	msg.success = success;
	set_resp_err(&msg);
	msg.dump = &resp;

	resp.has_restored = true;
	resp.restored = restored;

	return send_criu_msg(socket_fd, &msg);
}

static char images_dir[PATH_MAX];

static int setup_opts_from_req(int sk, CriuOpts *req){
	return 0;
/*
	struct ucred ids;
	struct stat st;
	socklen_t ids_len = sizeof(struct ucred);
	char images_dir_path[PATH_MAX];
	char work_dir_path[PATH_MAX];
	char status_fd[PATH_MAX];
	bool output_changed_by_rpc_conf = false;
	bool work_changed_by_rpc_conf = false;
	bool imgs_changed_by_rpc_conf = false;
	int i;
	bool dummy = false;

	if (getsockopt(sk, SOL_SOCKET, SO_PEERCRED, &ids, &ids_len)) {
		pr_perror("Can't get socket options");
		goto err;
	}

	if (fstat(sk, &st)) {
		pr_perror("Can't get socket stat");
		goto err;
	}

	service_sk_ino = st.st_ino;


	if (req->config_file) {
		char *tmp_output = NULL;
		char *tmp_work = NULL;
		char *tmp_imgs = NULL;

		if (opts.output)
			tmp_output = xstrdup(opts.output);
		if (opts.work_dir)
			tmp_work = xstrdup(opts.work_dir);
		if (opts.imgs_dir)
			tmp_imgs = xstrdup(opts.imgs_dir);
		free(opts.output);
		free(opts.work_dir);
		free(opts.imgs_dir);
		opts.output = NULL;
		opts.work_dir = NULL;
		opts.imgs_dir = NULL;
		rpc_cfg_file = req->config_file;
		i = parse_options(0, NULL, &dummy, PARSING_RPC_CONF);
		pr_warn("parse_options returns %d\n", i);
		if (i) {
			free(tmp_output);
			free(tmp_work);
			free(tmp_imgs);
			goto err;
		}
		if (tmp_output && imgs_changed_by_rpc_conf)
			strncpy(images_dir_path, opts,imgs_dir, PATH_MAX - 1);
		else
			sprintf(images_dir_path, "");
*/
}


static int dump_using_req(int sk, CriuOpts *req){
	bool success = false;
	bool self_dump = !req->pid;

	if (setup_opts_from_req(sk, req))
		goto exit;

	setproctitle("dump --rpc -t %d -D %s", req->pid, images_dir);

	if (cr_dump_tasks(req->pid))
		goto exit;

	success = true;
	return 0;
exit:
	if (req->leave_running || !self_dump || !success) {
		if (send_criu_dump_resp(sk, success, false) == -1) {
			pr_perror("Can't send response");
			success = false;
		}
	}

	return success ? 0 : 1;
}

static int restore_using_req(int sk, CriuOpts *req){
	return 0;
}

static int chk_keepopen_req(CriuReq *msg) {
	if (!msg->keep_open)
		return 0;

	if (msg->type == CRIU_REQ_TYPE__PAGE_SERVER)
		return 0;
//	if (msg->type == CRIU_REQ_TYPE__PAGE_SERVER_CHLD)
//		return 0;
//	else if (msg->type == CRIU_REQ_TYPE__VERSION)
//		return 0;

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


	if (chk_keepopen_req(msg))
		goto err;

	switch (msg->type) {
	case CRIU_REQ_TYPE__DUMP:
		ret = dump_using_req(sk, msg->opts);
		break;
	case CRIU_REQ_TYPE__RESTORE:
		ret = restore_using_req(sk, msg->opts);
		break;
	default:
		send_criu_err(sk, "Invalid req");
		break;
	}

	if (!ret && msg->keep_open) {
		criu_req__free_unpacked(msg, NULL);
		ret = -1;
		goto more;
	}
err:
	return ret;
}
