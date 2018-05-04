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


int main(void){
	int sock, sockpre;
	int fd;
	socklen_t socklen, size = sizeof(int);
	struct sockaddr_in srv_addr, cnt_addr;
	u_int32_t sndseq, rcvseq;
	int sndsize = 0, rcvsize = 0;
	char buf[256];
	char chs[] = "Welcome 000\n";
	int aux = 0, tmp = 0;
	char *sndqueue = NULL, *rcvqueue = NULL;
	char srcip[20], dstip[20];
	int srcpt, dstpt;
	struct msswnd mw;
	socklen_t mwsize = sizeof(mw);
	pid_t pid = getpid();

	sockpre = listen_port(9090);

	socklen = sizeof(struct sockaddr_in);
	sock = accept(sockpre, (struct sockaddr *)&cnt_addr, &socklen);

	getsockname(sock, (struct sockaddr *) &srv_addr, &socklen);
	strncpy(srcip, inet_ntoa(srv_addr.sin_addr), sizeof(srcip));
	strncpy(dstip, inet_ntoa(cnt_addr.sin_addr), sizeof(dstip));
	srcpt = ntohs(srv_addr.sin_port);
	dstpt = ntohs(cnt_addr.sin_port);

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
	aux = 1;
	setsockopt(sock, SOL_SOCKET, SO_REPAIR, &aux, size);
	getsockopt(sock, SOL_SOCKET, SO_REPAIR, &tmp, &size);
	printf("TCP repair mode: on\n");
	
	getsockopt(sock, SOL_SOCKET, SO_MSS_WINDOW, &mw, &mwsize);

	/* get sequence number of receive queue.(SO_QUEUE_SEQ)
	 * get size of packet in receive queue isn't used
	 * by application(FIONREAD).
	 * If size of packet in receive queue not equal 0,
	 * get(receive) data from receive queue. 
	 */
	aux = TCP_RECV_QUEUE;
	setsockopt(sock, SOL_SOCKET, SO_REPAIR_QUEUE, &aux, size);
	getsockopt(sock, SOL_SOCKET, SO_QUEUE_SEQ, &tmp, &size);
	rcvseq = tmp;

	if (ioctl(sock, FIONREAD, &rcvsize) == -1)
		perror("ioctl");

	if (rcvsize) {
		rcvqueue = malloc(rcvsize + 1);
		recv(sock, rcvqueue, rcvsize + 1, MSG_PEEK | MSG_DONTWAIT);
		printf("get rcvqueue: seq %x, size %x\n", rcvseq, rcvsize);
	}


	/* get sequence number of send queue.(SO_QUEUE_SEQ)
	 * get size of packet in send queue isn't send to
	 * destination(FIONWRITE).
	 * If size of packet in send queue not equal 0,
	 * get(receive) data from send queue. 
	 */
	aux = TCP_SEND_QUEUE;
	setsockopt(sock, SOL_SOCKET, SO_REPAIR_QUEUE, &aux, size);
	getsockopt(sock, SOL_SOCKET, SO_QUEUE_SEQ, &tmp, &size);
	sndseq = tmp;

	if (ioctl(sock, FIONWRITE, &sndsize) == -1)
		perror("ioctl");
	
	if (sndsize) {
		sndqueue = malloc(sndsize + 1);
		recv(sock, sndqueue, sndsize + 1, MSG_PEEK | MSG_DONTWAIT);
		printf("get sndqueue: seq %x, size %x\n", sndseq, sndsize);
	}

	close(sock);
	printf("socket close, don't send fin\n");


	setsockopt(sock, SOL_SOCKET, SO_REPAIR, &aux, size);
	printf("TCP repair mode: off\n");

	fd = open_dump_file(pid, "sndq");
	write(fd, sndqueue, sndsize);
	close(fd);


	fd = open_dump_file(pid, "rcvq");
	write(fd, rcvqueue, rcvsize);
	close(fd);


	fd = open_dump_file(pid, "sock");
	dprintf(fd, "%s,%d,%s,%d,%u,%u,%u,%u,%u,%u,%x,%d,%x,%d\n",
			srcip, srcpt, dstip, dstpt,
			mw.snd_wl1, mw.snd_wnd, mw.max_sndwnd,
			mw.rcv_wnd, mw.rcv_adv, mw.t_maxseg,
			sndseq, sndsize, rcvseq, rcvsize);
	close(fd);


	return 0;
}
