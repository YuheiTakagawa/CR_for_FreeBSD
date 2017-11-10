#include <stdio.h>
#include <unistd.h>

int main(char *args[]){
	int c;
	char ch[50] = {'\0'};
	for(c = 0; c < 5000; c++){
		snprintf(ch, sizeof(ch),  "Hello %d\n", c);
		write(1, ch, sizeof(ch));
		sleep(1);
	}
	return 0;
}
