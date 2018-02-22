#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdarg.h>

#include "syscall.h"
#include "string.c"
#include "rpc-pie-priv.h"
#include "parasite.h"
#include "infect-rpc.h"

#define NULL ((void *)0)

struct hello_pid{
	char hello[256];
	int pid;
};

struct parasite_init{
	int32_t h_addr_len;
	struct sockaddr_un h_addr;
};

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
//	//unsigned long new_sp;
	sys_close(tsock);
	return -1;
}

static int hp(struct hello_pid *hellop){
	char ch[] = "Hi, LOCAL. I'm DAEMON";
	memcpy(hellop->hello, ch, sizeof(ch));
	hellop->pid = sys_getpid();

	return 0;
}


int connection(void *data){
	struct parasite_init *args = data;
	struct ctl_msg m;
	char st[] = "I'M TAKAGAWA!\n";
	int i = 0;
	int tsock;
	int ret = 0;

	sys_write(1, st, 15); 

	tsock = sys_socket(PF_UNIX, SOCK_SEQPACKET, 0);
	if(tsock < 0){
		st[4] = 'O';
		sys_write(1, st, 15);
	}

	if(sys_connect(tsock, (struct sockaddr *)&args->h_addr, args->h_addr_len) < 0){
	}

	__parasite_daemon_reply_ack(tsock, PARASITE_CMD_INIT_DAEMON, 0);


	/* 
	 * waiting receive command from CRIU
	 * If getting command is PARASITE_CMD_FINI, closing and cure
	 */
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
				hp(data);

				break;
		}
		__parasite_daemon_reply_ack(tsock, m.cmd, ret); 
	}

	return 0;
}
