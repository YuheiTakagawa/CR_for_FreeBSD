#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "breakpoint.h"
#include "common.h"
#include "fds.h"
#include "ptrace.h"
#include "parasite_syscall.h"
#include "register.h"
#include "restorer.h"
#include "setmem.h"
#include "soccr/soccr.h"
#include "files.h"

#define IPFWDEL 1


int target(char *path, char* argv[]);

int target(char *path, char *argv[]){
	char *exec[] = {path, NULL};
	int ret;
	printf("CPID: %d\n", getpid());
	printf("command: %s\n", exec[0]);
	ptrace_traceme();

	ret = execvp(exec[0], exec);
	perror("execvp");
	exit(ret);
}

int restore_socket(int pid, int rfd) {
	int rst, fd;
	int tmp;
	int dsize;
	char *queue;
	char srcaddr[20], dstaddr[20];
	char buf [256];
	int srcpt, dstpt;
	struct libsoccr_sk *so_rst;
	struct libsoccr_sk_data data = {};
	union libsoccr_addr addr, dst;

	fd = open_file(pid, "sock");

	printf("start restore socket\n");
	read(fd, buf, sizeof(buf));
	strncpy(srcaddr, strtok(buf, ","), sizeof(srcaddr));
	srcpt = atoi(strtok(NULL, ","));
	strncpy(dstaddr, strtok(NULL, ","), sizeof(dstaddr));
	dstpt = atoi(strtok(NULL, ","));
	data.snd_wl1 = atoi(strtok(NULL, ","));
	data.snd_wnd = atoi(strtok(NULL, ","));
	data.max_window = atoi(strtok(NULL, ","));
	data.rcv_wnd = atoi(strtok(NULL, ","));
	data.rcv_wup = atoi(strtok(NULL, ","));
	data.mss_clamp = atoi(strtok(NULL, ","));
	data.outq_seq = strtol(strtok(NULL, ","), NULL, 16);
	data.outq_len = atoi(strtok(NULL, ","));
	data.inq_seq = strtol(strtok(NULL, ","), NULL, 16);
	data.inq_len = atoi(strtok(NULL, ","));
	data.unsq_len = atoi(strtok(NULL, ","));
	tmp = atoi(strtok(NULL, ","));
	close(fd);

	printf("close file\n");

	addr.v4.sin_family = AF_INET;
	addr.v4.sin_addr.s_addr = inet_addr(srcaddr);
	addr.v4.sin_port = htons(srcpt);

	dst.v4.sin_family = AF_INET;
	dst.v4.sin_addr.s_addr = inet_addr(dstaddr);
	dst.v4.sin_port = htons(dstpt);

	printf("create new socket\n");
	rst = socket(AF_INET, SOCK_STREAM, 0);

	dup2(rst, rfd);
	if(rst != rfd)
		close(rst);

	so_rst = libsoccr_pause(rfd);

	libsoccr_set_addr(so_rst, 1, &addr, 0);
	libsoccr_set_addr(so_rst, 0, &dst, 0);

	fd = open_file(pid, "sndq");
	queue = malloc(data.outq_len + 1);
	read(fd, queue, data.outq_len);
	libsoccr_set_queue_bytes(so_rst, TCP_SEND_QUEUE, queue, 0);
	close(fd);

	fd = open_file(pid, "rcvq");
	queue = malloc(data.inq_len + 1);
	read(fd, queue, data.inq_len);
	libsoccr_set_queue_bytes(so_rst, TCP_RECV_QUEUE, queue, 0);
	close(fd);
	

	printf("restore\n");
	dsize = sizeof(struct libsoccr_sk_data);
	libsoccr_restore(so_rst, &data, dsize);

	printf("resume so_rst\n");
	libsoccr_resume(so_rst);
/* unfilter packet */
	printf("unfilter packet\n");
//	setipfw(IPFWDEL, "192.168.11.1", "192.168.11.30");
	setipfw(IPFWDEL, srcaddr, dstaddr);

	return 0;
}

int restore_fork(int filePid, char *exec_path){
	pid_t pid;
	int fd;
	int i;
	struct restore_fd_struct fds[1024];
	read_fd_list(filePid, fds);
	for(i = 0; fds[i].fd != -2 ; i++){
		printf("fd:%d, off:%ld, path:%s\n", fds[i].fd, fds[i].offset, fds[i].path);
		/*
		 *  if restore tty info, have to implement restoring ttys
		 */
		if(strstr(fds[i].path, "/dev/pts") == NULL){
			if((strstr(fds[i].path, "socket") != NULL) || 
				(strstr(fds[i].path, "internet") != NULL)){
				restore_socket(filePid, fds[i].fd);
				continue;
			}else if(!strcmp(fds[i].path, "local"))
				continue;
			fd = prepare_restore_files(fds[i].path, fds[i].fd, fds[i].offset);
		}
	}
	pid = fork();
	if(pid < 0){
		perror("FORK");
		exit(1);
	}
	if(pid != 0){
		for(i = 0; fds[i].fd != -2; i++) {
			if(fds[i].fd > 2)
				close(fd);
		}
		return pid;
	}
	target(exec_path, NULL);
	return 0;
}

int restore(pid_t rpid, char *rpath){
	int status;
	pid_t pid;
	struct orig orig;
	struct remap_vm_struct revm[BUFSIZE];

	printf("CMD : %s\n", rpath);
	printf("PPID: %d\n", getpid());
	printf("Restore file: %d\n", rpid); 

	pid = restore_fork(rpid, rpath);
	printf("finish fork\n");
	insert_breakpoint(pid, rpath);
	printf("finish insert breakpoint\n");
	remap_vm(pid, rpid, revm, &orig);
	
	waitpro(pid, &status);
	setmems(pid, rpid, revm);
/* TODO
   To restore registers with rt_sigreturn.
   inject code pie/restorer.c to running processes with linuxulator
   call restore_threads() from src/restorer.c
*/
	restore_threads(pid, rpid);
//	setregs(pid, rpid);
//	step_debug(pid);

//	ptrace_cont(pid);
	
	waitpro(pid, &status);
	print_regs(pid);
//	step_debug(pid);

	/*
	 * To keep attach
	 * if detach from process, uncomment ptrace_detach
	 */
//	while(1){}
	ptrace_detach(pid);
	
	return 0;
}
	
/*
int main(int argc, char* argv[]){
	int rpid;
	char *rpath;

	if(argc < 3){
		printf("Usage: %s <path> <file pid>\n", argv[0]);
		exit(1);
	}

	rpath = argv[1];
	rpid = atoi(argv[2]);

	restore(rpid, rpath);
	return 0;
}
*/
