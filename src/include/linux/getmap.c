#ifndef __GET_VM_
#define __GET_VM_

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

//#include <libprocstat.h>

#define BUF_SIZE 1024
#define PATH_BUF 1024

struct vmds{
	unsigned long int dsize;
	unsigned long int ssize;
	unsigned long int daddr;
	unsigned long int saddr;
};

void get_vmmap(int pid, struct vmds* vmds){

	char buf[BUF_SIZE] = {'\0'};
	char path[PATH_BUF] = {'\0'};
	int i = 0;
	char *str;

	snprintf(path, PATH_BUF, "/proc/%d/smaps", pid);
	FILE *fp = fopen(path, "r");

	while(fgets(buf, BUF_SIZE, fp) != NULL){
		if(i == 1){
			str = strtok(buf, " ");
			str = strtok(NULL, " ");
			vmds->ssize = atoi(str) * 1024;
			i++;
			break;
		}

		if(strstr(buf, "[stack]") != NULL){
			str = strtok(buf, "-");
			vmds->saddr = strtoul(str, &str, 16);
			i++;
		}
	} 	

	vmds->dsize = 0x28000;
	vmds->daddr = 0x6c9000;

	printf("stack data: %lx\n", vmds->dsize);
	printf("stack size: %lx\n", vmds->ssize);

//	procstat_freevmmap(prst, (void *)kp);
}

#endif
