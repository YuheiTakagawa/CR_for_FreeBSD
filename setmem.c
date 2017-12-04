#include <unistd.h>

int setmems(pid_t, pid_t);
int open_file(pid_t, char*);
int write_mem(int, int, long int);

int setmems(pid_t pid, pid_t filePid){
        int write_fd;
        int read_fd;
        char buf[BUFSIZE];

        write_fd = open_file(pid, "mem");
        

        read_fd = open_file(filePid, "data");
        write_mem(read_fd, write_fd, 0x6c9000); 

        read_fd = open_file(filePid, "stack");
        write_mem(read_fd, write_fd, 0x7ffffffdf000);

        close(write_fd);
        return 0;
}

int open_file(pid_t pid, char* flag){
        char filepath[PATHBUF];

        if(flag == "mem"){
                snprintf(filepath, sizeof(filepath), "/proc/%d/mem", pid);
                return  open(filepath, O_WRONLY);
        }
        snprintf(filepath, sizeof(filepath), "/dump/%d_%s.img", pid, flag);
        return open(filepath, O_RDONLY);
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

