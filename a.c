#include <stdio.h>
//#include <signal.h>

//typedef void __signalfn(int) *__sighandler_t;

typedef void __restorefn_t(void);
typedef __restorefn_t *__sigrestore_t;

typedef struct {
	unsigned long int __val[1024/(8*sizeof(unsigned long int))];
}__sigset_t;

struct linuxsigaction {
	void (*__sigaction_handler) (int);
	__sigset_t sa_mask;
	int sa_flags;
	void (*sa_restorer) (void);
};

void main() {
///	printf("size: %d\n", sizeof(struct sigaction));
	printf("size: %d\n", sizeof(struct linuxsigaction));
}
