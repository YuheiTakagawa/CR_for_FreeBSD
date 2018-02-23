#ifndef GETFD
#define GETFD

#include "common.h"

struct restore_fd_struct{
	int fd;
	char path[BUFSIZE];
	off_t offset;
};

struct fd_list{
	int fd[FD_MAX];
	char *path[FD_MAX];
	off_t offset[FD_MAX];
};

extern int prepare_restore_files(char *path, int fd, off_t foff);
extern void read_fd_list(pid_t filePid, struct restore_fd_struct *fds);
extern int *get_open_fd(pid_t pid, struct fd_list *fdl);
extern int getfd(pid_t pid);

#endif
