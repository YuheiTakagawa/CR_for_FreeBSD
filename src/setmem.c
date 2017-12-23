#ifndef SETMEM
#define SETMEM

#include <unistd.h>

#include "files.h"

#define BUFSIZE 1024
#define PATHBUF 30

int setmems(pid_t, pid_t, unsigned long int);
int write_mem(int, int, long int);

int setmems(pid_t pid, pid_t filePid, unsigned long int stack_addr){
        int write_fd;
        int read_fd;

        write_fd = open_file(pid, "mem");
        

        read_fd = open_file(filePid, "data");
        write_mem(read_fd, write_fd, 0x6c9000); 

        read_fd = open_file(filePid, "stack");
        write_mem(read_fd, write_fd, stack_addr);

        close(write_fd);
        return 0;
}

int write_mem(int read_fd, int write_fd, long int offset){
        char buf[BUFSIZE];
        int rnum;

        lseek(write_fd, offset, SEEK_SET);

        while(1){

                rnum = read(read_fd, buf, sizeof(buf));
                if(rnum > 0){
                        write(write_fd, buf, rnum);
                }else{
                        close(read_fd);
                        break;
                }
        }
        return rnum;
}

#endif
