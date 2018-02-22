#include "syslib.c"

int parasite_service(int cmd, void *args){
	int i = 0;
	i = 100;
	connection(args);
	return i*i;
}
