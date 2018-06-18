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

#define IPFWDEL 1

int main(int argc, char *argv[]){
	int rst;
	pid_t pid;
	int fd;
	int dsize;
	char buf[256];
	char chs[] = "Welcome 000\n";
	char *queue;
	char srcip[20], dstip[20];
	int srcpt, dstpt;
	struct libsoccr_sk *so_rst;
	struct libsoccr_sk_data data = {};
	union libsoccr_addr addr, dst;

	if(argc < 2) {
		printf("usage: ./restorenet <restore pid>\n");
		exit(1);
	}

	pid = atoi(argv[1]);
	fd = open_file(pid, "sock");
	read(fd, buf, sizeof(buf));
	strncpy(srcip, strtok(buf, ","), sizeof(srcip));
	srcpt = atoi(strtok(NULL, ","));
	strncpy(dstip, strtok(NULL, ","), sizeof(dstip));
	dstpt = atoi(strtok(NULL, ","));
	data.snd_wl1 = atoi(strtok(NULL, ","));
	data.snd_wnd = atoi(strtok(NULL, ","));
	data.max_window = atoi(strtok(NULL, ","));
	data.rcv_wnd = atoi(strtok(NULL, ","));
	data.rcv_wup = atoi(strtok(NULL, ","));
	data.mss_clamp = atoi(strtok(NULL, ","));
	data.outq_seq = strtol(strtok(NULL, ","), NULL, 16);
	data.outq_len = atoi(strtok(NULL, ","));
	data.inq_seq = strtol(strtok(NULL, ","), NULL, 16);
	data.inq_len = atoi(strtok(NULL, ","));
	data.unsq_len = atoi(strtok(NULL, ","));
	close(fd);


	addr.v4.sin_family = AF_INET;
	addr.v4.sin_addr.s_addr = inet_addr(srcip);
	addr.v4.sin_port = htons(srcpt);

	dst.v4.sin_family = AF_INET;
	dst.v4.sin_addr.s_addr = inet_addr(dstip);
	dst.v4.sin_port = htons(dstpt);

	printf("create new socket\n");
	rst = socket(AF_INET, SOCK_STREAM, 0);

	so_rst = libsoccr_pause(rst);

	libsoccr_set_addr(so_rst, 1, &addr, 0);
	libsoccr_set_addr(so_rst, 0, &dst, 0);

	fd = open_file(pid, "sndq");
	queue = malloc(data.outq_len + 1);
	read(fd, queue, data.outq_len);
	libsoccr_set_queue_bytes(so_rst, TCP_SEND_QUEUE, queue, 0);
	close(fd);

	fd = open_file(pid, "rcvq");
	queue = malloc(data.inq_len + 1);
	read(fd, queue, data.inq_len);
	libsoccr_set_queue_bytes(so_rst, TCP_RECV_QUEUE, queue, 0);
	close(fd);


	dsize = sizeof(struct libsoccr_sk_data);
	libsoccr_restore(so_rst, &data, dsize);

	libsoccr_resume(so_rst);

	/* unfilter packet */
	printf("unfilter packet\n");
	setipfw(IPFWDEL, srcip, dstip);

	snprintf(chs, sizeof(chs), "RESTORE FINISHED\n");
	write(rst, chs, sizeof(chs));
	printf("fini\n");
	while(1){}
	/*while(read(rst, chs, sizeof(chs))){
		printf("recv %s\n", chs);
		usleep(100000);
	}*/

	return 0;
}
