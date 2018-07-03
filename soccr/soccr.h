#ifndef __LIBSOCCR_H__
#define __LIBSOCCR_H__
#include <netinet/in.h>
#include <sys/socket.h>

struct libsoccr_sk;

union libsoccr_addr {
	struct sockaddr sa;
	struct sockaddr_in v4;
	struct sockaddr_in6 v6;
};

struct libsoccr_sk_data {
	uint32_t	state;
	uint32_t	inq_len;
	uint32_t	inq_seq;
	uint32_t	outq_len;
	uint32_t	outq_seq;
	uint32_t	unsq_len;
	uint32_t	opt_mask;
	uint32_t	mss_clamp;
	uint32_t	snd_wscale;
	uint32_t	rcv_wscale;
	uint32_t	timestamp;

	uint32_t	flags;
	uint32_t	snd_wl1;
	uint32_t	snd_wl2;
	uint32_t	snd_wnd;
	uint32_t	max_window;
	uint32_t	rcv_wnd;
	uint32_t	rcv_wup;
	uint32_t	snd_scale;
};

void setipfw(int, char*, char*);
struct libsoccr_sk *libsoccr_pause(int fd);
void libsoccr_resume(struct libsoccr_sk *sk);

void libsoccr_release(struct libsoccr_sk *sk);

int libsoccr_save(struct libsoccr_sk *sk, struct libsoccr_sk_data *data, unsigned data_size);

char *libsoccr_get_queue_bytes(struct libsoccr_sk *sk, int queue_id, unsigned flags);
int libsoccr_set_queue_bytes(struct libsoccr_sk *sk, int queue_id, char *bytes, unsigned flags);

int libsoccr_set_addr(struct libsoccr_sk *sk, int self, union libsoccr_addr *, unsigned flags);

int libsoccr_restore(struct libsoccr_sk *sk, struct libsoccr_sk_data *data, unsigned data_size);

#endif
