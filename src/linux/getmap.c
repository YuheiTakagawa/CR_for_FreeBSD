#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "files.h"
#include "getmap.h"

void get_vmmap(int pid, struct vmds* vmds, int flag){

	char path[PATHBUF] = {'\0'};
	char b[BUFSIZE];
	char tmp[BUFSIZE];
	int i = 0;
	char *str;
	long start, end;
	int flags;
	char protection[5];
	int size;

	int write_fd;
	if(flag == DUMP_VMMAP)
		write_fd = open_dump_file(pid, "map");

	snprintf(path, PATHBUF, "/proc/%d/maps", pid);
	FILE *fp = fopen(path, "r");

	while(fgets(b, BUFSIZE, fp) != NULL){
		str = strtok(b, "-");
		start = strtoul(str, &str, 16);
		str = strtok(NULL, " ");
		end = strtoul(str, &str, 16);
		flags = 0x0;
		str = strtok(NULL, " ");
		//protection = 0x0;
		//use protection as string
		strncpy(protection, str, sizeof(protection));

		for(int i = 0; i < 4; i++){
			str = strtok(NULL, " ");
		}
		
		printf("===============================\n");
		printf("begin: %lx, end: %lx, flag: %x\n", start, end, flags);
		printf("prot: %s, path: %s\n", protection, str);
/*
 * TODO
 * - dump protection with binary number(hex)
 * - dump flags from smaps
 */
		if(flags == 0x0 && /*protection == 0x3*/!strncmp("rw-p", protection, sizeof(protection))){// data segment but linux's it is separated data and heap
			if(strstr(str, "/") != NULL){
				vmds->haddr = start;
				vmds->hsize = end - start;
				flags = 0x1;
			//	continue;
			}
		}

		if(/*flags == GROWS_DOWN || */strstr(str, "[stack]") != NULL){//stack
			vmds->saddr = start;
			vmds->ssize = end - start;
			/* MAP_GROWSDOWN of Linux is 0x100.
			 * On FreeBSD, MAP_GROWSDOWN is 0x20.
			 */
			flags = 0x100;
			//continue;
		}

		if(flag == DUMP_VMMAP){
			char *buf = str;
			if(strlen(buf) == 0)
				buf = " ";
			size = snprintf(tmp, sizeof(tmp), "%lx,%lx,%x,%x,%s", start, end, flags, 0x7, buf);
			//size = snprintf(tmp, sizeof(tmp), "%lx,%lx,%x,%s,%s", start, end, flags, protection, buf);
			write(write_fd, tmp, size);
		}
		
	}
/*
	snprintf(path, PATHBUF, "/proc/%d/smaps", pid);
	FILE *fp = fopen(path, "r");

	while(fgets(buf, BUFSIZE, fp) != NULL){
		if(strstr(buf, "rd ex") != NULL){
			if(i == 0){
				i++;
			}
			continue;
		}

		if(i == 1){
			str = strtok(buf, "-");
			vmds->haddr = strtoul(str, &str, 16);
			i++;
			continue;
		}

		if(i == 2){
			str = strtok(buf, " ");
			str = strtok(NULL, " ");
			vmds->hsize = atoi(str) * 1024;
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
*/
	printf("data size: %lx\n", vmds->hsize);
	printf("data addr: %lx\n", vmds->haddr);
	printf("stack size: %lx\n", vmds->ssize);
	printf("stack addr: %lx\n", vmds->saddr);

}

void show_vmmap(pid_t pid, struct vmds *vmds){
	get_vmmap(pid, vmds, SHOW_VMMAP);
}

void dump_vmmap(pid_t pid, struct vmds *vmds){
	get_vmmap(pid, vmds, DUMP_VMMAP);
}
