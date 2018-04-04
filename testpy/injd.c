#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/wait.h>

int main(void){
	char *strenv;
	int status;

	int sock;
	int sockfd;

	int namelen;

	char buf[32];
	int pid;
	int size;

	struct sockaddr_in server;
	struct sockaddr_in client;

	//sock = socket(AF_INET, SOCK_STREAM, 0);
	sock = socket(AF_INET, SOCK_DGRAM, 0);

	server.sin_family = AF_INET;
	server.sin_port = htons(8090);
	server.sin_addr.s_addr = INADDR_ANY;

	bind(sock, (struct sockaddr *)&server, sizeof(server));

	listen(sock, 1);

	while(1){
		memset(buf, 0, sizeof(buf));
		size = read(sock, buf, sizeof(buf));
		if(size < 0){
			break;
		}
		printf("recv: %s", buf);
		
		pid = fork();
		if(pid == 0){
			execl("/CR_for_FreeBSD/testpy/search.sh", "./search.sh", buf, NULL);
		}else{
			waitpid(pid, NULL, 0);
		}
	}
	/*
	while(1){
		namelen = sizeof(client);
		sockfd = accept(sock, (struct sockaddr *) &client, &namelen);
	
		pid = fork();
		if(pid == 0){
			printf("wait data\n");
			read(sockfd, buf, sizeof(buf));
			printf("recv: %s", buf);
			execl("/CR_for_FreeBSD/testpy/search.sh", "./search.sh", buf, NULL);
			break;
		}else{
			waitpid(pid, NULL, 0);
			close(sockfd);

		}
	}
	*/
	close(sock);

	return 0;
}
