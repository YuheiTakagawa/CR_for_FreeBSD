#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdarg.h>

struct ctl_msg {
	uint32_t	cmd;			/* command itself */
	uint32_t	ack;			/* ack on command */
	int32_t		err;			/* error code on reply */
};

#define ctl_msg_cmd(_cmd)		\
	(struct ctl_msg){.cmd = _cmd, }

#define ctl_msg_ack(_cmd, _err)	\
	(struct ctl_msg){.cmd = _cmd, .ack = _cmd, .err = _err, }

#define NULL ((void *)0)

enum {
	PARASITE_CMD_IDLE		= 0,
	PARASITE_CMD_ACK,

	PARASITE_CMD_INIT_DAEMON,

	/*
	 * This must be greater than INITs.
	 */
	PARASITE_CMD_FINI,

	__PARASITE_END_CMDS,
};

#define PARASITE_USER_CMDS 64
enum {
	PARASITE_CMD_DUMP_THREAD = PARASITE_USER_CMDS,
	PARASITE_CMD_MPROTECT_VMAS,
	PARASITE_CMD_DUMPPAGES,

	PARASITE_CMD_DUMP_SIGACTS,
	PARASITE_CMD_DUMP_ITIMERS,
	PARASITE_CMD_DUMP_POSIX_TIMERS,
	PARASITE_CMD_DUMP_MISC,
	PARASITE_CMD_DRAIN_FDS,
	PARASITE_CMD_GET_PROC_FD,
	PARASITE_CMD_DUMP_TTY,
	PARASITE_CMD_CHECK_VDSO_MARK,
	PARASITE_CMD_CHECK_AIOS,
	PARASITE_CMD_DUMP_CGROUP,
	PARASITE_CMD_GET_PID,

	PARASITE_CMD_MAX,
};

extern long sys_write(int fd, const void *buf, unsigned long count);
extern long sys_read(int fd, const void *buf, unsigned long count);
extern long sys_close(int fd);
extern long sys_getpid(void);
extern long sys_socket(int domain, int type, int protocol);
extern long sys_connect(int sockfd, struct sockaddr *addr, int addrlen);
extern long sys_sendto(int sockfd, void *buff, size_t len, unsigned int flags, struct sockaddr *addr, int addr_len);
extern long sys_recvfrom(int sockfd, void *buf, size_t len, unsigned int flags, struct sockaddr *addr, int addr_len);

struct parasite_init_args{
	int32_t h_addr_len;
	struct sockaddr_un h_addr;
};




static const char conv_tab[] = "0123456789abcdefghijklmnopqrstuvwxyz";
void std_dputc(int fd, char c)
{
	sys_write(fd, &c, 1);
}

void std_dputs(int fd, const char *s)
{
	for (; *s; s++)
		std_dputc(fd, *s);
}

static size_t __std_vprint_long_hex(char *buf, size_t blen, unsigned long num, char **ps)
{
	char *s = &buf[blen - 2];

	buf[blen - 1] = '\0';

	if (num == 0) {
		*s = '0', s--;
		goto done;
	}

	while (num > 0) {
		*s = conv_tab[num % 16], s--;
		num /= 16;
	}

done:
	s++;
	*ps = s;
	return blen - (s - buf);
}

static size_t __std_vprint_long(char *buf, size_t blen, long num, char **ps)
{
	char *s = &buf[blen - 2];
	int neg = 0;

	buf[blen - 1] = '\0';

	if (num < 0) {
		neg = 1;
		num = -num;
	} else if (num == 0) {
		*s = '0';
		s--;
		goto done;
	}

	while (num > 0) {
		*s = (num % 10) + '0';
		s--;
		num /= 10;
	}

	if (neg) {
		*s = '-';
		s--;
	}
done:
	s++;
	*ps = s;
	return blen - (s - buf);
}

void std_vdprintf(int fd, const char *format, va_list args)
{
	const char *s = format;

	for (; *s != '\0'; s++) {
		char buf[32], *t;
		int along = 0;

		if (*s != '%') {
			std_dputc(fd, *s);
			continue;
		}

		s++;
		if (*s == 'l') {
			along = 1;
			s++;
			if (*s == 'l')
				s++;
		}

		switch (*s) {
		case 's':
			std_dputs(fd, va_arg(args, char *));
			break;
		case 'd':
			__std_vprint_long(buf, sizeof(buf),
					  along ?
					  va_arg(args, long) :
					  (long)va_arg(args, int),
					  &t);
			std_dputs(fd, t);
			break;
		case 'x':
			__std_vprint_long_hex(buf, sizeof(buf),
					      along ?
					      va_arg(args, long) :
					      (long)va_arg(args, int),
					      &t);
			std_dputs(fd, t);
			break;
		}
	}
}

void std_dprintf(int fd, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	std_vdprintf(fd, format, args);
	va_end(args);
}

static int __parasite_daemon_reply_ack(int tsock, unsigned int cmd, int err)
{
	struct ctl_msg m;
	int ret;

	m = ctl_msg_ack(cmd, err);
	ret = sys_sendto(tsock, &m, sizeof(m), 0, NULL, 0);
	if (ret != sizeof(m)) {
		return -1;
	}

	return 0;
}

static int __parasite_daemon_wait_msg(int tsock, struct ctl_msg *m)
{
	int ret;


	while (1) {
		*m = (struct ctl_msg){ };
		ret = sys_recvfrom(tsock, m, sizeof(*m), MSG_WAITALL, NULL, 0);
		if (ret != sizeof(*m)) {
			return -1;
		}

		return 0;
	}

	return -1;
}

static int fini(int tsock){
	//unsigned long new_sp;
	sys_close(tsock);
	return -1;
}

#define STDOUT_FILENO 1
#define std_printf(fmt, ...)	std_dprintf(1, fmt, ##__VA_ARGS__)

int connection(void *data){
	char st[] = "I'M TAKAGAWA!\n";
	int i = 0;
	struct parasite_init_args *args = data;
	int tsock = sys_socket(PF_UNIX, SOCK_SEQPACKET, 0);
	struct ctl_msg m;
	int ret = 0;

	sys_write(1, st, 15);
	//for(int i = 0; i < 0x10000000; i++){}
	if(tsock < 0){
		st[4] = 'O';
		sys_write(1, st, 15);
	}
	/*
	sys_write(1, args->h_addr.sun_path, 17);
	std_printf("sun_path:%s\n", args->h_addr.sun_path);
	std_printf("family:%d\n", args->h_addr.sun_family);
	std_printf("size%d\n", args->h_addr_len);
	*/
	if(sys_connect(tsock, (struct sockaddr *)&args->h_addr, args->h_addr_len) < 0){
		//st[3] = 'K';
		//sys_write(1, st, 15);
	}
	//char ch[100] = "Hi, LOCAL\n I'm REMOTE";
	__parasite_daemon_reply_ack(tsock, PARASITE_CMD_INIT_DAEMON, 0);
	while(1){
		__parasite_daemon_wait_msg(tsock, &m);
		std_printf("local msg: %d\n", m.cmd);
		if(m.cmd == PARASITE_CMD_FINI){
			fini(tsock);
			break;
		}
		switch(m.cmd){
			case PARASITE_CMD_GET_PID:
				ret = sys_getpid();
				std_printf("my pid: %d\n", ret);
				break;
		}
		__parasite_daemon_reply_ack(tsock, m.cmd, ret); 
	}

	return 0;
}

