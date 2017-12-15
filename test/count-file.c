#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(char *args[]){
	int c;
	int fd;
	char ch[50] = {'\0'};

	fd = open("/dump/hello", O_RDWR | O_CREAT, S_IRWXU);
	printf("opened FD: %d\n", fd);
	for(c = 0; c < 5000; c++){
		snprintf(ch, sizeof(ch),  "Hello %d\n", c);
		write(fd, ch, sizeof(ch));
		sleep(1);
	}
	return 0;
}
