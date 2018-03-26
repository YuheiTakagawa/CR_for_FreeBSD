#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern int restore(pid_t pid, char *path);
extern int tracing(pid_t pid);

int usage(void){
	printf(	"Usage\n"
		"  ./criu dump -p PID\n"
		"  ./criu restore -p PID -e PATH\n"
		"Other options:\n"
		"  -h|help	show this\n"
	      );
	return 0;
}

int main(int argc, char *argv[]){
	int i;
	int pid = 0;
	char *path = NULL;
	struct option longopts[] = {
		{ "pid",	required_argument,	0, 'p' },
		{ "help",	no_argument,		0, 'h' },
		{ },
	};

	if(argc < 2){
		goto usage;
	}

	int opt;
	int longindex;
	while((opt = getopt_long(argc, argv, "p:e:h", longopts, &longindex)) != -1){
		switch(opt){
			case 'p':
				pid = atoi(optarg);
				break;
			case 'e':
				path = optarg;
				break;
			case 'h':
				usage();
				return 0;
			default:
				printf("err %c %c\n", opt, optopt);
				return 1;
		}
	}

	for(i = optind; i < argc; i++){
		if(!(strcmp(argv[i], "restore"))){
			if(path == NULL)
				goto usage;
			if(pid == 0)
				goto usage;
			restore(pid, path);
			break;
		}
		if(!(strcmp(argv[i], "dump"))){
			if(pid == 0)
				goto usage;
			tracing(pid);
			break;
		}
		goto usage;
	}
	return 0;

usage:
	usage();
	return -1;
}
