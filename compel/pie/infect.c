#include "syslib.c"

int parasite_service(int cmd, void *args){
	int i = 0;
	i = 100;
	connection(args);
//	sys_exit(0);
	return 0;
}
