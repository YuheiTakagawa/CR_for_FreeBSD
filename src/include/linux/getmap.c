#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "files.h"
#include "getmap.h"

void get_vmmap(int pid, struct vmds* vmds, int flag){

	char buf[BUF_SIZE] = {'\0'};
	char path[PATH_BUF] = {'\0'};
	int i = 0;
	char *str;

	snprintf(path, PATH_BUF, "/proc/%d/smaps", pid);
	FILE *fp = fopen(path, "r");

	while(fgets(buf, BUF_SIZE, fp) != NULL){
		if(strstr(buf, "rd ex") != NULL){
			if(i == 0){
				i++;
			}
			continue;
		}

		if(i == 1){
			str = strtok(buf, "-");
			vmds->daddr = strtoul(str, &str, 16);
			i++;
			continue;
		}

		if(i == 2){
			str = strtok(buf, " ");
			str = strtok(NULL, " ");
			vmds->dsize = atoi(str) * 1024;
			i++;
			continue;
		}

		if(strstr(buf, "[stack]") != NULL){
			str = strtok(buf, "-");
			vmds->saddr = strtoul(str, &str, 16);
			i++;
			continue;
		}

		if(i == 4){
			str = strtok(buf, " ");
			str = strtok(NULL, " ");
			vmds->ssize = atoi(str) * 1024;
			i = 0;
			break;
		}

	} 	

	printf("data size: %lx\n", vmds->dsize);
	printf("data addr: %lx\n", vmds->daddr);
	printf("stack size: %lx\n", vmds->ssize);
	printf("stack addr: %lx\n", vmds->saddr);

}

void show_vmmap(pid_t pid, struct vmds *vmds){
	get_vmmap(pid, vmds, SHOW_VMMAP);
}

void dump_vmmap(pid_t pid, struct vmds *vmds){
	get_vmmap(pid, vmds, DUMP_VMMAP);
}
