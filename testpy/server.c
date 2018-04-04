#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

int main(void){
	int sock;
	int sockfd;
	int namelen;
	int size;
	struct sockaddr_in server;
	struct sockaddr_in client;
	char buf[32];

	sock = socket(AF_INET, SOCK_STREAM, 0);

	server.sin_family = AF_INET;
	server.sin_port = htons(8080);
	server.sin_addr.s_addr = INADDR_ANY;

	bind(sock, (struct sockaddr *)&server, sizeof(server));

	listen(sock, 1);
	namelen = sizeof(client);
	sockfd = accept(sock, (struct sockaddr *) &client, &namelen);
	printf("wait data\n");

	while(size = read(sockfd, buf, sizeof(buf)) != -1){
		write(1, buf, size);
	}
	close(sock);
	close(sockfd);

	return 0;
}
