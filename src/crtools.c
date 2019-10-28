#include <sys/socket.h>
#include <sys/un.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "cr-service.h"
#include "protobuf.h"

extern int restore(pid_t pid, char *path, int dfd);
extern int tracing(pid_t pid, int * options);

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
	char *dpath = NULL;
	int options[10];
	struct option longopts[] = {
		{ "version",	no_argument,		0, 'V' },
		{ "pid",	required_argument,	0, 'p' },
		{ "d",		required_argument,	0, 'd' },
		{ "help",	no_argument,		0, 'h' },
		{ "tcp",	no_argument,		0, 't' },
	};

	if(argc < 2){
		goto usage;
	}

	int opt;
	int longindex;
	while((opt = getopt_long(argc, argv, "p:e:d:Vht", longopts, &longindex)) != -1){
		switch(opt){
			case 'V':
				printf("Version: 3.1\n");
				break;
			case 'p':
				pid = atoi(optarg);
				break;
			case 'e':
				path = optarg;
				break;
			case 'd':
				dpath = optarg;
				printf("dpath: %s\n", dpath);
				break;
			case 't':
				options[0] = 1;
				break;
			case 'h':
				usage();
				return 0;
			default:
				printf("err %c %c\n", opt, optopt);
				return 1;
		}
	}

	cr_pb_init();

	for(i = optind; i < argc; i++){
		if(!(strcmp(argv[i], "restore"))){
			if(path == NULL)
				goto usage;
			if(pid == 0)
				goto usage;
			int dfd = open(dpath, O_DIRECT);
			cr_restore_tasks(pid, path, dfd);
			break;
		}
		if(!(strcmp(argv[i], "dump"))){
			if(pid == 0)
				goto usage;
			tracing(pid, options);
			break;
		}
		if(!(strcmp(argv[i], "swrk"))){
			if(argc < 3)
				goto usage;
			printf("swrk des\n");
			struct sockaddr_un sa;
			int sock = socket(PF_UNIX, SOCK_SEQPACKET, 0);
			if (sock == -1) {
				printf("socket\n");
				return -1;
			}

			sa.sun_family = PF_UNIX;
			strcpy(sa.sun_path, "/criu-fifo");
			if(connect(sock, (struct sockaddr*)&sa, sizeof(struct sockaddr_un)) == -1) {
				printf("connect\n");
				close(sock);
				return -1;
			}

			dup2(sock, atoi(argv[2]));
			cr_service_work(atoi(argv[2]));
			close(sock);
			break;
		}
		goto usage;
	}
	return 0;

usage:
	usage();
	return -1;
}
