#include <unistd.h>

int main(void){
	char tmp[] = "Hello Injection!\n";
	write(1, tmp, sizeof(tmp));
	return 0;
}
