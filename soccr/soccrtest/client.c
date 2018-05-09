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
	char tmp[9];
	int count = 0;
	srand(time(NULL));
        sockfd	= socket(AF_INET, SOCK_STREAM, 0);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	addr.sin_port = htons(9090);

	if(connect(sockfd, (struct sockaddr *) &addr, sizeof(addr)) < 0)
		perror("connect");


	if(write(sockfd, buf, sizeof(buf)) < 0)
		perror("write");

	while(read(sockfd, tmp, sizeof(tmp))){
		//snprintf(buf, sizeof(buf), "HELLO %05d\n", count++);
		//write(sockfd, buf, sizeof(buf));
		printf("from sv: %s\n", tmp);
//		usleep(100000);
	//	memset(tmp, '\0', sizeof(tmp));
	}

	return 0;
}

