#ifndef ASM_SYSCALL_PROTO_H_64__
#define ASM_SYSCALL_PROTO_H_64__

struct msghdr;

extern long sys_write(int fd, const void *buf, unsigned long count);
extern long sys_read(int fd, const void *buf, unsigned long count);
extern long sys_close(int fd);
extern long sys_getpid(void);
extern long sys_recvmsg(int sockfd, struct msghdr *msg, int flags);
extern long sys_sendmsg(int sockfd, const struct msghdr *msg, int flags);
//extern long sys_sendmsg(int sockfd, const struct msghdr *msg, int flags);
extern long sys_socket(int domain, int type, int protocol);
extern long sys_connect(int sockfd, struct sockaddr *addr, int addrlen);
extern long sys_sendto(int sockfd, void *buff, size_t len, unsigned int flags, struct sockaddr *addr, int addr_len);
extern long sys_recvfrom(int sockfd, void *buf, size_t len, unsigned int flags, struct sockaddr *addr, int addr_len);
extern void sys_exit(int status);

#endif
