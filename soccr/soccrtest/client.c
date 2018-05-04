#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main (void){
	printf("AF_INET %d\n", AF_INET);
	int sockfd;
	struct sockaddr_in addr;
	char buf[] = "HELLO WORLD\n";
	char tmp[13];
	int count = 0;
	srand(time(NULL));
        sockfd	= socket(AF_INET, SOCK_STREAM, 0);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("192.168.11.1");
	addr.sin_port = htons(9090);

	connect(sockfd, (struct sockaddr *) &addr, sizeof(addr));

	write(sockfd, buf, sizeof(buf));

	while(count < 500){
		//snprintf(buf, sizeof(buf), "HELLO %05d\n", count++);
		//write(sockfd, buf, sizeof(buf));
		memset(tmp, '\0', sizeof(tmp));
		recv(sockfd, tmp, sizeof(tmp), MSG_WAITALL);
		printf("from sv: %s\n", tmp);
		usleep(100000);
	}

	return 0;
}

