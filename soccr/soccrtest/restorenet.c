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

int main(int argc, char *argv[]){
	int rst;
	pid_t pid;
	int fd;
	socklen_t socklen = sizeof(struct sockaddr_in), size = sizeof(int);
	struct sockaddr_in srv_addr, cnt_addr;
	u_int32_t sndseq, rcvseq;
	int sndsize = 0, rcvsize = 0;
	char buf[256];
	char ipfw[256];
	char chs[] = "Welcome 000\n";
	int aux = 0;
	char *sndqueue = NULL, *rcvqueue = NULL;
	char srcip[20], dstip[20];
	int srcpt, dstpt;
	struct msswnd mw;
	socklen_t mwsize = sizeof(mw);

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
	mw.snd_wl1 = atoi(strtok(NULL, ","));
	mw.snd_wnd = atoi(strtok(NULL, ","));
	mw.max_sndwnd = atoi(strtok(NULL, ","));
	mw.rcv_wnd = atoi(strtok(NULL, ","));
	mw.rcv_adv = atoi(strtok(NULL, ","));
	mw.t_maxseg = atoi(strtok(NULL, ","));
	sndseq = strtol(strtok(NULL, ","), NULL, 16);
	sndsize = atoi(strtok(NULL, ","));
	rcvseq = strtol(strtok(NULL, ","), NULL, 16);
	rcvsize = atoi(strtok(NULL, ","));
	close(fd);

	fd = open_file(pid, "sndq");
	sndqueue = malloc(sndsize + 1);
	read(fd, sndqueue, sndsize);
	close(fd);

	fd = open_file(pid, "rcvq");
	rcvqueue = malloc(rcvsize + 1);
	read(fd, rcvqueue, rcvsize);
	close(fd);


	srv_addr.sin_family = AF_INET;
	srv_addr.sin_addr.s_addr = inet_addr(srcip);
	srv_addr.sin_port = htons(srcpt);

	printf("create new socket\n");
	rst = socket(AF_INET, SOCK_STREAM, 0);

	aux = 1;
	setsockopt(rst, SOL_SOCKET, SO_REPAIR, &aux, size);	


	if (bind (rst, (struct sockaddr *) &srv_addr, socklen) == -1)
		perror("bind");

	/* set sequence number before connect. */

	aux = TCP_RECV_QUEUE;
	setsockopt(rst, SOL_SOCKET, SO_REPAIR_QUEUE, &aux, size);
	setsockopt(rst, SOL_SOCKET, SO_QUEUE_SEQ, &rcvseq, sizeof(rcvseq));
	printf("set repair rcv seq %x\n", rcvseq);

	aux = TCP_SEND_QUEUE;
	setsockopt(rst, SOL_SOCKET, SO_REPAIR_QUEUE, &aux, size);
	setsockopt(rst, SOL_SOCKET, SO_QUEUE_SEQ, &sndseq, sizeof(sndseq));
	printf("set repair snd seq %x\n", sndseq);

	setsockopt(rst, SOL_SOCKET, SO_MSS_WINDOW, &mw, mwsize);

	cnt_addr.sin_family = AF_INET;
	cnt_addr.sin_addr.s_addr = inet_addr(dstip);
	cnt_addr.sin_port = htons(dstpt);

	if (connect(rst, (struct sockaddr *) &cnt_addr, sizeof(cnt_addr)) == -1)
		perror("connect");


	if (rcvqueue != NULL || rcvsize) {
		aux = TCP_RECV_QUEUE;
		setsockopt(rst, SOL_SOCKET, SO_REPAIR_QUEUE, &aux, size);
		send(rst, rcvqueue, rcvsize, 0); 
		printf("restore rcvqueue\n");
	}
	
	if (sndqueue != NULL || sndsize) {
		aux = TCP_SEND_QUEUE;
		setsockopt(rst, SOL_SOCKET, SO_REPAIR_QUEUE, &aux, size);
		send(rst, sndqueue, sndsize, 0); 
		printf("restore sndqueue\n");
	}

	aux = 0;
	setsockopt(rst,  SOL_SOCKET, SO_REPAIR, &aux, size);
	printf("TCP repair mode: off\n");


	/* unfilter packet */
	printf("unfilter packet\n");
	snprintf(ipfw, sizeof(ipfw), "./ipfw.sh delete");
	system(ipfw);

	snprintf(chs, sizeof(chs), "RESTORE FINISHED\n");
	write(rst, chs, sizeof(chs));

	return 0;
}
