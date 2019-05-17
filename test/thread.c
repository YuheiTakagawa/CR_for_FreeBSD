#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <pthread.h>
#include <unistd.h>
#define THREADS_NUM 1

struct threada{
#define _pthread_startzero tid
	long tid;
};

void *counter(void *args){
	int i;
	pid_t pid;
	pthread_t thread_id;

	pid = getpid();
	thread_id=pthread_self();
	for(i=0; i<1000;i++){
		usleep(100000);
		printf("[%d][%d]%d\n", pid, ((struct threada*)thread_id)->tid, i);
	}
	return args;
}


void main(void){
	pid_t pid;
	pthread_t thread_id[THREADS_NUM];
	int status, i;
	void *result;

	pid = getpid();
	printf("[%d]start\n", pid);

	for (i=0; i < THREADS_NUM; i++){
		status = pthread_create(&thread_id[i], NULL, counter,(void *)NULL);
		if (status != 0){
			fprintf(stderr, "pthread_create:%s", strerror(status));
		} else {
			printf("[%d] thread_id=%d\n", pid, thread_id[i]);
		}
	}
	for(i=0; i < THREADS_NUM; i++){
		pthread_join(thread_id[i], &result);
		printf("[%d]thread_id%d=%d end\n", pid, i, thread_id[i]);
	}
	printf("[%d]end\n", pid);
}

