#include <unistd.h>

void parasite_service(void){
	write(1, "Hello Injection\n", 17);
}
