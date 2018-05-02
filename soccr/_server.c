#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

int main(void){
	int sock, sockpre, rst;
	socklen_t server_len, client_len, size = sizeof(int);
	struct sockaddr_in server_address;
	struct sockaddr_in client_address;
	u_int32_t sndseq, rcvseq;
	int sndsize = 0, rcvsize = 0;
	char buf[256];
	char chs[] = "Welcome 000\n";
	int count = 0;
	int aux = 0, tmp = 0;
	char *sndqueue = NULL, *rcvqueue = NULL, *tmptest = NULL;

	sockpre = socket(AF_INET, SOCK_STREAM, 0);
	server_address.sin_family = AF_INET;
	server_address.sin_addr.s_addr = INADDR_ANY;
	server_address.sin_port = htons(9090);

	aux = 1;
	setsockopt(sockpre, SOL_SOCKET, SO_REUSEADDR, (const char *) &aux, sizeof(aux));

	server_len = sizeof(server_address);
	bind (sockpre, (struct sockaddr *) &server_address, server_len);

	if (listen(sockpre, 5) == -1){
		perror("listen");
		exit(1);
	}
	client_len = sizeof(client_address);
	sock = accept(sockpre, (struct sockaddr *)&client_address, &client_len);

	getsockname(sock, (struct sockaddr *) &server_address, &server_len);


	read(sock, buf, sizeof(buf));
	printf("from client %s", buf);

	for(int i = 0; i < 100; i++){
		snprintf(chs, sizeof(chs), "Welcome %03d\n", i);
		write(sock, chs, sizeof(chs));
/*
		if (recv(sock, chs, sizeof(chs), MSG_DONTWAIT) == -1)
			perror("recv");

		printf("from cl: %s\n", chs);
*/
		usleep(100000);
	}

	/* REPAIR MODE ON */
	aux = 1;
	setsockopt(sock, SOL_SOCKET, SO_REPAIR, &aux, size);
	getsockopt(sock, SOL_SOCKET, SO_REPAIR, &tmp, &size);
	printf("TCP repair mode: on\n");
	

	/* please, packet filter on
	 * TODO on FreeBSD, packet filter with ipfw
	 * so implement packet filter in this. */
	printf("please, drop packet\n");
	sleep(10);

	


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



	printf("create new socket\n");
	rst = socket(AF_INET, SOCK_STREAM, 0);

	aux = 1;
	setsockopt(rst, SOL_SOCKET, SO_REPAIR, &aux, size);


	if (bind (rst, (struct sockaddr *) &server_address, server_len) == -1)
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


	if (connect(rst, (struct sockaddr *) &client_address, sizeof(client_address)) == -1)
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
	setsockopt(sock, SOL_SOCKET, SO_REPAIR, &aux, size);
	setsockopt(rst,  SOL_SOCKET, SO_REPAIR, &aux, size);
	printf("TCP repair mode: off\n");


	/* please, unfilter packet */
	printf("please, allow packet\n");
	sleep(10);


		snprintf(chs, sizeof(chs), "FINISHED\n");
		write(rst, chs, sizeof(chs));
/*
	while(1){
		if (recv(rst, chs, sizeof(chs), MSG_WAITALL) == -1)
			perror("recv");

		printf("from cl: %s\n", chs);
		usleep(50000);
	}
*/
	return 0;
}
