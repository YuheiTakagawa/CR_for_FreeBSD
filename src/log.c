#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/utsname.h>

#include <fcntl.h>

#include <pthread.h>

#include "servicefd.h"
#include "log.h"


#define DEFAULT_LOGFD		STDERR_FILENO
#define LOG_TIMESTAMP		(DEFAULT_LOGLEVEL + 1)
#define LOG_BUF_LEN		(8*1024)


static unsigned int current_loglevel = DEFAULT_LOGLEVEL;

static char buffer[LOG_BUF_LEN];
static char buf_off = 0;

static struct timeval start;

#define TS_BUF_OFF	12

static void timediff(struct timeval *from, struct timeval *to) {
	to->tv_sec -= from->tv_sec;
	if (to->tv_usec >= from->tv_usec)
		to->tv_usec -= from->tv_usec;
	else {
		to->tv_sec--;
		to->tv_usec += 1000000 - from->tv_usec;
	}
}

static void print_ts(void) {
	struct timeval t;

	gettimeofday(&t, NULL);
	timediff(&start, &t);
	snprintf(buffer, TS_BUF_OFF,
			"(%02u.%06u)", (unsigned)t.tv_sec, (unsigned)t.tv_usec);
	buffer[TS_BUF_OFF - 1] = ' ';
}

int log_get_fd(void) {
	int fd = get_service_fd(LOG_FD_OFF);

	return fd < 0 ? DEFAULT_LOGFD : fd;
}

struct str_and_lock {
	pthread_mutex_t l;
	char s[1024];
};

static struct str_and_lock *first_err;

static void log_note_err(char *msg) {
	if (first_err && first_err->s[0] == '\0') {
		pthread_mutex_lock(&first_err->l);
		if (first_err->s[0] == '\0')
			strlcpy(first_err->s, msg, sizeof(first_err->s));
		pthread_mutex_unlock(&first_err->l);
	}
}

char *log_first_err(void) {
	if (!first_err)
		return NULL;
	if (first_err->s[0] == '\0')
		return NULL;

	return first_err->s;
}

void vprint_on_level(unsigned int loglevel, const char *format, va_list params) {
	int fd, size, ret, off = 0;
	int __errno = errno;

	if (loglevel == LOG_MSG) {
		fd = STDOUT_FILENO;
		off = buf_off;
	} else {
		if (loglevel > current_loglevel)
			return;
		fd = log_get_fd();
		if (current_loglevel >= LOG_TIMESTAMP)
			print_ts();
	}

	size = vsnprintf(buffer + buf_off, sizeof buffer - buf_off, format, params);
	size += buf_off;

	while (off < size) {
		ret = write(fd, buffer + off, size - off);
		if (ret <= 0)
			break;
		off += ret;
	}

	if (loglevel == LOG_ERROR)
		log_note_err(buffer + buf_off);

	errno = __errno;
}

void print_on_level(unsigned int loglevel, const char *format, ...){
	va_list params;

	va_start(params, format);
	vprint_on_level(loglevel, format, params);
	va_end(params);
}
