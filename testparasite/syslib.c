#include <sys/types.h>
#include <sys/socket.h>
extern long sys_write(int fd, const void *buf, unsigned long count);
extern long sys_socket(int domain, int type, int protocol);
//extern long sys_connect(int sockfd, struct sockaddr *addr, int addrlen);
//extern long sys_sendto(int sockfd, void *buff, size_t len, unsigned int flags, struct sockaddr *addr, int addr_len);


int connection(void){
	char st[] = "I'M TAKAGAWA!\n";
	sys_write(1, st, 15);
	sys_socket(PF_UNIX, SOCK_SEQPACKET, 0);
	return 0;
}

