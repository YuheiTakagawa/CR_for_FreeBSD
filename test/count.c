#include <unistd.h>
int main(char *args[]){
	int c;
	//char ch[50] = {'\0'};
	char ch[50] = "Hello\n";
	for(c = 0; c < 5000000; c++){
		ch[2] ++;
		write(1, ch, sizeof(ch));
	}
	return 0;
}
