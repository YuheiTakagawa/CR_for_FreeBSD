#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

#include "common.h"
#include "files.h"
#include "../soccr.h"

#define IPFWADD 0
#define IPFWDEL 1

int listen_port(int port) {
	int sockpre;
	socklen_t size;
	struct sockaddr_in addr;
	int aux;
	
	sockpre = socket(AF_INET, SOCK_STREAM, 0);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);
	aux = 1;
	setsockopt(sockpre, SOL_SOCKET, SO_REUSEADDR, (const char *) &aux, sizeof(aux));
	size = sizeof(addr);
	bind (sockpre, (struct sockaddr *) &addr, size);

	if (listen(sockpre, 5) == -1){
		perror("listen");
		exit(1);
	}
	return sockpre;
}

int main(void){
	int sock, sockpre;
	int fd;
	socklen_t socklen;
	struct sockaddr_in addr, dst;
	int dsize = 0;
	char buf[256];
	char chs[] = "Welcome 000\n";
	char *queue;
	char srcip[20], dstip[20];
	int srcpt, dstpt;
	pid_t pid = getpid();
	struct libsoccr_sk_data data = {};
	struct libsoccr_sk *so;

	sockpre = listen_port(9090);

	socklen = sizeof(struct sockaddr_in);
	sock = accept(sockpre, (struct sockaddr *)&dst, &socklen);

	getsockname(sock, (struct sockaddr *) &addr, &socklen);
	strncpy(srcip, inet_ntoa(addr.sin_addr), sizeof(srcip));
	strncpy(dstip, inet_ntoa(dst.sin_addr), sizeof(dstip));
	srcpt = ntohs(addr.sin_port);
	dstpt = ntohs(dst.sin_port);

	read(sock, buf, sizeof(buf));
	printf("from client %s", buf);

	for(int i = 0; i < 100; i++){
		snprintf(chs, sizeof(chs), "Welcome %03d\n", i);
		write(sock, chs, sizeof(chs));
		if(i == 43) {
			setipfw(IPFWADD, srcip, dstip);
		}
		usleep(100000);
	}

	/* REPAIR MODE ON */
	so = libsoccr_pause(sock);

	dsize = libsoccr_save(so, &data, sizeof(data));
	if (dsize < 0) {
		perror("libsoccr_save");
		return 1;
	}

	close(sock);
	printf("socket close, don't send fin\n");

	queue = libsoccr_get_queue_bytes(so, TCP_RECV_QUEUE, 0);
	fd = open_dump_file(pid, "rcvq");
	write(fd, queue, data.inq_len);
	close(fd);

	queue = libsoccr_get_queue_bytes(so,  TCP_SEND_QUEUE, 0);
	fd = open_dump_file(pid, "sndq");
	write(fd, queue, data.outq_len);
	close(fd);


	libsoccr_resume(so);
	printf("TCP repair mode: off\n");

	fd = open_dump_file(pid, "sock");
	dprintf(fd, "%s,%d,%s,%d,%u,%u,%u,%u,%u,%u,%x,%d,%x,%d\n",
			srcip, srcpt, dstip, dstpt,
			data.snd_wl1, data.snd_wnd, data.max_window,
			data.rcv_wnd, data.rcv_wup, data.mss_clamp,
			data.outq_seq, data.outq_len, data.inq_seq, data.inq_len);
	close(fd);


	return 0;
}
