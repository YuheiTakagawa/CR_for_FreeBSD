#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

extern long sys_write(int fd, const void *buf, unsigned long count);
extern long sys_socket(int domain, int type, int protocol);
extern long sys_connect(int sockfd, struct sockaddr *addr, int addrlen);
extern long sys_sendto(int sockfd, void *buff, size_t len, unsigned int flags, struct sockaddr *addr, int addr_len);

struct parasite_init_args{
	int32_t h_addr_len;
	struct sockaddr_un h_addr;
};

int connection(void *data){
	char st[] = "I'M TAKAGAWA!\n";
	sys_write(1, st, 15);
	struct parasite_init_args *args = data;
	int tsock = sys_socket(PF_UNIX, SOCK_SEQPACKET, 0);
	sys_connect(tsock, (struct sockaddr *)&args->h_addr, args->h_addr_len);
	sys_write(tsock, &st[3], 1);
	return 0;
}

