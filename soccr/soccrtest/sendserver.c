#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

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

	sockpre = listen_port(9090);

	socklen = sizeof(struct sockaddr_in);
	printf("waiting\n");
	sock = accept(sockpre, (struct sockaddr *)&dst, &socklen);
	if (sock < 0)
		perror("accept");
	/*
	sock = socket(AF_INET, SOCK_STREAM, 0);
	dst.sin_family = AF_INET;
	dst.sin_port = htons(9090);
	dst.sin_addr.s_addr = inet_addr("192.168.11.30");

	connect(sock, (struct sockaddr *)&dst, socklen);
*/
	getsockname(sock, (struct sockaddr *) &addr, &socklen);
	strncpy(srcip, inet_ntoa(addr.sin_addr), sizeof(srcip));
	strncpy(dstip, inet_ntoa(dst.sin_addr), sizeof(dstip));
	srcpt = ntohs(addr.sin_port);
	dstpt = ntohs(dst.sin_port);

	read(sock, buf, sizeof(buf));
	printf("from client %s", buf);
//	write(sock, chs, sizeof(chs));

	for(int i = 0; i < 10000; i++){
		//read(sock, chs, sizeof(chs));
		//printf("rsds %s\n", chs);
		snprintf(chs, sizeof(chs), "wel %03d\n", i);
		write(sock, chs, sizeof(chs));
		usleep(100000);
		memset(chs, 0, sizeof(chs));
	}
	return 0;
}
