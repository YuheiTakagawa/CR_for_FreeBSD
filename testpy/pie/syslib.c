#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdarg.h>
#include <time.h>
#include <fcntl.h>

#include "syscall.h"
#include "string.c"
#include "rpc-pie-priv.h"
#include "parasite.h"
#include "infect-rpc.h"

#define NULL ((void *)0)

int connection(void *data){
	char st[] = "I'M TAKAGAWA!\n";
	int pid;
	struct timespec tp;
	tp.tv_sec = 5;
	tp.tv_nsec = 0;
	char outpath[] = "/hey";
	//char inpath[] = "/b.tmp";
	int outfd = sys_open(outpath, O_RDWR);

	sys_dup2(outfd, 1);

	sys_close(outfd);
	
//	int infd = sys_open(inpath, O_RDWR);

//	sys_dup2(infd, 0);
/*
 * This is multi process for writing
 */
/*	pid = sys_fork();
	if(pid == 0){
		while(1){
			sys_write(0, st, 15); 
			sys_nanosleep(&tp, NULL);
		}
	}
*/


	return 0;
}
