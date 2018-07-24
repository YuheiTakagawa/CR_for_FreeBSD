#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp_fsm.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

#include "soccr.h"
#define IPFWADD 0
#define IPFWDEL 1


void setipfw(int flag, char *sip, char *dip){
	char ipfw[256];

	switch(flag) {
	case IPFWADD:
		snprintf(ipfw, sizeof(ipfw), "ipfw.sh add %s %s", sip, dip);
		break;
	case IPFWDEL:
		snprintf(ipfw, sizeof(ipfw), "ipfw.sh delete %s %s", sip, dip);
		break;
	}
	system(ipfw);
}

static int tcp_repair_on(int fd) {
	int ret = 1, aux = 1;

	ret = setsockopt(fd, SOL_SOCKET, SO_REPAIR, &aux, sizeof(aux));
	if (ret < 0)
		printf("Can't turn TCP repair mode ON\n");

	return ret;
}

static int tcp_repair_off(int fd) {
	int ret = -1 , aux = 0;

	ret = setsockopt(fd, SOL_SOCKET, SO_REPAIR, &aux, sizeof(aux));
	if (ret < 0){
		perror("setsockopt");
		printf("Failed to turn off repair mode on socket\n");
	}

	return ret;
}

struct libsoccr_sk {
	int fd;
	unsigned flags;
	char *recv_queue;
	char *send_queue;
	union libsoccr_addr *src_addr;
	union libsoccr_addr *dst_addr;
};

#define SK_FLAG_FREE_RQ		0x1
#define SK_FLAG_FREE_SQ		0x2
#define SK_FLAG_FREE_SA		0x4
#define SK_FLAG_FREE_DA		0x8

struct libsoccr_sk *libsoccr_pause(int fd)
{
	struct libsoccr_sk *ret;

	ret = malloc(sizeof(*ret));
	if (!ret) {
		printf("Unable to allocate memory\n");
		return NULL;
	}

	if (tcp_repair_on(fd) < 0) {
		free(ret);
		return NULL;
	}

	ret->flags = 0;
	ret->recv_queue = NULL;
	ret->send_queue = NULL;
	ret->src_addr = NULL;
	ret->dst_addr = NULL;
	ret->fd = fd;
	return ret;
}

void libsoccr_resume(struct libsoccr_sk *sk)
{
	tcp_repair_off(sk->fd);
	libsoccr_release(sk);
}

void libsoccr_close(struct libsoccr_sk *sk)
{
	close(sk->fd);
}

void libsoccr_release(struct libsoccr_sk *sk)
{
	if (sk->flags & SK_FLAG_FREE_RQ)
		free(sk->recv_queue);
	if (sk->flags & SK_FLAG_FREE_SQ)
		free(sk->send_queue);
	if (sk->flags & SK_FLAG_FREE_SA)
		free(sk->src_addr);
	if (sk->flags & SK_FLAG_FREE_DA)
		free(sk->dst_addr);
	free(sk);
}

static int refresh_sk(struct libsoccr_sk *sk,
		struct libsoccr_sk_data *data)
{
	int size;

	data->state = TCPS_ESTABLISHED;

	if (ioctl(sk->fd, FIONWRITE, &size) == -1) {
		perror("ioctl");
		return -1;
	}

	printf("outq_len %d\n", size);
	data->outq_len = size;

	if (ioctl(sk->fd, FIONUNWRITE, &size) == -1) {
		perror("ioctl");
		return -1;
	}

	printf("unsq_len %d\n", size);
	data->unsq_len = size;

	if (ioctl(sk->fd, FIONREAD, &size) == -1) {
		perror("ioctl");
		return -1;
	}

	data->inq_len = size;

	return 0;
}

static int get_window(struct libsoccr_sk *sk, struct libsoccr_sk_data *data)
{
	struct msswnd mw;
	socklen_t len = sizeof(mw);

	getsockopt(sk->fd, SOL_SOCKET, SO_MSS_WINDOW, &mw, &len);

	data->snd_wl1		= mw.snd_wl1;
	data->snd_wnd		= mw.snd_wnd;
	data->max_window	= mw.max_sndwnd;
	data->rcv_wnd		= mw.rcv_wnd;
	data->rcv_wup		= mw.rcv_adv;
	data->mss_clamp		= mw.t_maxseg;
	data->snd_scale		= mw.snd_scale;

	return 0;
}

/* get sequence number of send/recv queue.(SO_QUEUE_SEQ)
 * get size of packet in send/recv queue isn't send/recv to
 * destination/application(FIONWRITE/FIONREAD).
 * If size of packet in send/recv queue not equal 0,
 * get(receive) data from send/recv queue. 
 */

static int get_queue(int sk, int queue_id,
		uint32_t *seq, uint32_t len, char **bufp)
{
	int ret, aux;
	socklen_t auxl;
	char *buf;

	aux = queue_id;
	auxl = sizeof(aux);
	ret = setsockopt(sk, SOL_SOCKET, SO_REPAIR_QUEUE, &aux, auxl);
	if (ret < 0)
		goto err_sopt;

	auxl = sizeof(*seq);
	ret = getsockopt(sk, SOL_SOCKET, SO_QUEUE_SEQ, seq, &auxl);
	if (ret < 0)
		goto err_sopt;

	if (len) {
		buf = malloc(len + 1);
		if (!buf) {
			printf("Unable to allocate memory\n");
			goto err_buf;
		}

		ret = recv(sk, buf, len + 1, MSG_PEEK | MSG_DONTWAIT);
		if (ret != len)
			goto err_recv;
	}else
		buf = NULL;

	*bufp = buf;
	return 0;

err_sopt:
	printf("\ttsockopt failed\n");
err_buf:
	return -1;

err_recv:
	printf("\trecv failed (%d, want %d)", ret, len);
	free(buf);
	goto err_buf;
}

int libsoccr_save(struct libsoccr_sk *sk, struct libsoccr_sk_data *data, unsigned data_size)
{
	memset(data, 0, data_size);

	if (refresh_sk(sk, data))
		return -2;

	if (get_window(sk, data))
		return -4;

	sk->flags |= SK_FLAG_FREE_SQ | SK_FLAG_FREE_RQ;

	if (get_queue(sk->fd, TCP_RECV_QUEUE, &data->inq_seq, data->inq_len, &sk->recv_queue))
		return -5;

	if (get_queue(sk->fd, TCP_SEND_QUEUE, &data->outq_seq, data->outq_len, &sk->send_queue))
		return -6;

	return sizeof(struct libsoccr_sk_data);
}

char *libsoccr_get_queue_bytes(struct libsoccr_sk *sk, int queue_id, unsigned flags)
{
	char **p, *ret;

	switch (queue_id) {
		case TCP_RECV_QUEUE:
			p = &sk->recv_queue;
			break;
		case TCP_SEND_QUEUE:
			p = &sk->send_queue;
			break;
		default:
			return NULL;
	}

	ret = *p;

	return ret;
}

static int set_queue_seq(struct libsoccr_sk *sk, int queue, uint32_t seq)
{
	printf("\tSetting %d queue seq to %u\n", queue, seq);

	if (setsockopt(sk->fd, SOL_SOCKET, SO_REPAIR_QUEUE, &queue, sizeof(queue)) < 0) {
		printf("Can't set repair seq\n");
		return -1;
	}

	if (setsockopt(sk->fd, SOL_SOCKET, SO_QUEUE_SEQ, &seq, sizeof(seq)) < 0) {
		printf("Can't set queue seq\n");
		return -1;
	}

	return 0;
}

static int libsoccr_set_sk_data_noq(struct libsoccr_sk *sk,
		struct libsoccr_sk_data *data, unsigned data_size)
{
	int addr_size;

	if (sk->src_addr->sa.sa_family == AF_INET)
		addr_size = sizeof(sk->src_addr->v4);
	else
		addr_size = sizeof(sk->src_addr->v6);

	if (bind(sk->fd, &sk->src_addr->sa, addr_size)) {
		perror("bind");
		return -1;
	}

	if (set_queue_seq(sk, TCP_RECV_QUEUE,
//				data->inq_seq - data->inq_len))
				data->inq_seq))
		return -2;

	if (set_queue_seq(sk, TCP_SEND_QUEUE,
				data->outq_seq - data->outq_len))
		return -3;

	if (sk->dst_addr->sa.sa_family == AF_INET)
		addr_size = sizeof(sk->dst_addr->v4);
	else
		addr_size = sizeof(sk->dst_addr->v6);

	if (data->state == TCPS_SYN_SENT && tcp_repair_off(sk->fd))
		return -1;

	if (connect(sk->fd, &sk->dst_addr->sa, addr_size) == -1 &&
			errno != EINPROGRESS) {
		printf("Can't connect inet socket back\n");
		return -1;
	}

	if (data->state == TCPS_SYN_SENT && tcp_repair_off(sk->fd))
		return -1;

	return 0;
}

static int libsoccr_restore_queue(struct libsoccr_sk *sk, struct libsoccr_sk_data *data, unsigned data_size,
		int queue, char *buf);

int libsoccr_restore(struct libsoccr_sk *sk,
		struct libsoccr_sk_data *data, unsigned data_size)
{
	if (libsoccr_set_sk_data_noq(sk, data, data_size))
		return -1;


	struct msswnd mw = {
		.snd_wl1 = data->snd_wl1,
		.snd_wnd = data->snd_wnd,
	//	.snd_wnd = 65664,
		.max_sndwnd = data->max_window,
		.rcv_wnd = data->rcv_wnd,
		.rcv_adv = data->rcv_wup,
		.t_maxseg = data->mss_clamp,
		.snd_scale = data->snd_scale,
	};
	setsockopt(sk->fd, SOL_SOCKET, SO_MSS_WINDOW, &mw, sizeof(mw));

	if (libsoccr_restore_queue(sk, data, sizeof(*data), TCP_RECV_QUEUE, sk->recv_queue))
		return -1;
			char srcaddr[20], dstaddr[20];
			strncpy(srcaddr, inet_ntoa(sk->src_addr->v4.sin_addr), sizeof(srcaddr));
			strncpy(dstaddr, inet_ntoa(sk->dst_addr->v4.sin_addr), sizeof(srcaddr));
			setipfw(IPFWDEL, srcaddr, dstaddr);

	if (libsoccr_restore_queue(sk, data, sizeof(*data), TCP_SEND_QUEUE, sk->send_queue))
		return -1;
	
	return 0;
}

static int __send_queue(struct libsoccr_sk *sk, int queue, char *buf, uint32_t len)
{
	int ret, err = -1, max_chunk;
	int off;

	max_chunk = len;
	off = 0;

	do {
		int chunk = len;

		if (chunk > max_chunk)
			chunk = max_chunk;

		printf("off: %d, chunk %d\n", off, chunk);
		ret = send(sk->fd, buf + off, chunk, 0);
		perror("send");
		printf("send ret: %d\n", ret);
		if (ret <= 0) {
			if (max_chunk > 1024) {
				max_chunk >>= 1;
				continue;
			}
			
			goto err;
		}

		off += ret;
		len -= ret;
	} while (len);

	err = 0;

err:
	return err;
/*
	printf("len %d\n", len);
	ret = send(sk->fd, buf, len, 0);
	printf("ret %d\n", ret);
*/

}

static int send_queue(struct libsoccr_sk *sk, int queue, char *buf, uint32_t len)
{
	printf("\tRestoring TCP %d queue data %u bytes\n", queue, len);

	if (setsockopt(sk->fd, SOL_SOCKET, SO_REPAIR_QUEUE, &queue, sizeof(queue)) < 0) {
		perror("Can't set repair queue");
		return -1;
	}

	return __send_queue(sk, queue, buf, len);
}

static int libsoccr_restore_queue(struct libsoccr_sk *sk, struct libsoccr_sk_data *data, unsigned data_size,
		int queue, char *buf)
{
	if (!buf)
		return 0;

	if (queue == TCP_RECV_QUEUE) {
		if (!data->inq_len)
			return 0;
		return send_queue(sk, TCP_RECV_QUEUE, buf, data->inq_len);
	}

	if (queue == TCP_SEND_QUEUE) {
		uint32_t len, ulen;

		ulen = data->unsq_len;
		len = data->outq_len - ulen;
		printf("len %d, ulen %d\n", len, ulen);
		if (len && send_queue(sk, TCP_SEND_QUEUE, buf, len))
			return -2;

		if (ulen) {
			tcp_repair_off(sk->fd);
		
		if (__send_queue(sk, TCP_SEND_QUEUE, buf + len, ulen))
				return -3;
			if (tcp_repair_on(sk->fd))
				return -4;
		}

		return 0;
	}

	return -5;
}

int libsoccr_set_queue_bytes(struct libsoccr_sk *sk, int queue_id, char *bytes, unsigned flags)
{
	switch (queue_id) {
		case TCP_RECV_QUEUE:
			sk->recv_queue = bytes;
			return 0;
		case TCP_SEND_QUEUE:
			sk->send_queue = bytes;
			return 0;
	}
	return -1;
}

int libsoccr_set_addr(struct libsoccr_sk *sk, int self, union libsoccr_addr *addr, unsigned flags)
{
	if (self) {
		sk->src_addr = addr;
	} else {
		sk->dst_addr = addr;
	}

	return 0;
}
