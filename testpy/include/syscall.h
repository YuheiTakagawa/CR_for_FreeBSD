#ifndef ASM_SYSCALL_PROTO_H_64__
#define ASM_SYSCALL_PROTO_H_64__

extern long sys_fork(void);
extern long sys_write(int fd, const void *buf, unsigned long count);
extern long sys_read(int fd, const void *buf, unsigned long count);
extern long sys_open(const char* path, int flags);
extern long sys_close(int fd);
extern long sys_getpid(void);
extern long sys_pipe2(int pipe[2], int flag);
extern long sys_socket(int domain, int type, int protocol);
extern long sys_connect(int sockfd, struct sockaddr *addr, int addrlen);
extern long sys_sendto(int sockfd, void *buff, size_t len, unsigned int flags, struct sockaddr *addr, int addr_len);
extern long sys_recvfrom(int sockfd, void *buf, size_t len, unsigned int flags, struct sockaddr *addr, int addr_len);
extern long sys_dup2(int oldfd, int newfd);
extern long sys_nanosleep(const struct timespec *tp, struct timespec *rem);

#endif
