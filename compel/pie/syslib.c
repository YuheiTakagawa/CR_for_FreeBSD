#define NULL ((void *)0)

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "syscall.h"
#include "string.c"
#include "rpc-pie-priv.h"
#include "parasite.h"
#include "infect-rpc.h"


static int tsock = -1;


struct hello_pid{
	char hello[256];
	int pid;
};

struct parasite_init{
	int32_t h_addr_len;
	struct sockaddr_un h_addr;
};

struct linux_msghdr {
	void 		*msg_name;
	socklen_t	msg_namelen;
	struct iovec	*msg_iov;
	size_t		msg_iovlen;
	void		*msg_control;
	size_t		msg_controllen;
	int		msg_flags;
};

struct linux_cmsghdr {
	size_t		cmsg_len;
	int		cmsg_level;
	int		cmsg_type;
};

static int __parasite_daemon_reply_ack(unsigned int cmd, int err)
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

static int __parasite_daemon_wait_msg(struct ctl_msg *m)
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

static int fini(void){
//	//unsigned long new_sp;
	sys_close(tsock);
	return -1;
}

struct linux_sockaddr_un {
	unsigned short sun_family;
	char sun_path[108];
};

int connect_gate(const char* path)
{
	int gate;
	int ret;
	struct linux_sockaddr_un gate_addr;
	/* SOCK_DGRAMを使う */
	if ( (gate = sys_socket(PF_UNIX, SOCK_DGRAM, 0)) < 0 ) {
		return -1;
	}
	memset(&gate_addr, 0, sizeof(gate_addr));
	gate_addr.sun_family = PF_UNIX;
	memcpy(gate_addr.sun_path, path, sizeof(gate_addr.sun_path));
	*(gate_addr.sun_path + sizeof(gate_addr.sun_path)) = '\0';
	if ((ret = sys_connect(gate, (struct sockaddr*)&gate_addr, sizeof(gate_addr))) < 0 ) {
		std_printf("fault connect %d\n", ret);
		return -1;
	}
	std_printf("fini connect %d\n", gate);
	return gate;
}


/*
int recvfd(int gate, void* message, size_t message_len)
{
	struct msghdr msg;
	struct iovec iov;
	char cmsgbuf[CMSG_SPACE(sizeof(int))];

	iov.iov_base = message;
	iov.iov_len = message_len;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);
	msg.msg_flags = MSG_WAITALL;

	if ( sys_recvmsg(gate, &msg, 0) < 0 ) {
		return -1;
	}

	struct cmsghdr *cmsg = (struct cmsghdr*)cmsgbuf;
	return *((int *)CMSG_DATA(cmsg));
}
*/


int sendfd(int gate, int fd, void* message, int message_len)
{
	int ret;
	struct iovec iov;
	char cmsgbuf[CMSG_SPACE(sizeof(int))];
//	char cmsgbuf[(_ALIGN(sizeof(struct cmsghdr)) + _ALIGN(sizeof(int)))];

	iov.iov_base = message;
	iov.iov_len = message_len;

	struct cmsghdr *cmsg = (struct cmsghdr*)cmsgbuf;
//	struct cmsghdr *cmsg = (struct cmsghdr*)cmsgbuf;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
//	cmsg->cmsg_len = (_ALIGN(sizeof(struct cmsghdr)) + sizeof(int));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*((int *)CMSG_DATA(cmsg)) = fd;
//	*((int *)((void*)((char*)cmsg + _ALIGN(sizeof(struct cmsghdr))))) = fd;

	//struct msghdr msg;
	struct msghdr msg;
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);
	msg.msg_flags = 0;

	if ((ret = sys_sendmsg(gate, &msg, 0)) < 0) {
		std_printf("err sendmsg %d\n", ret);
		return -1;
	}
	std_printf("fini sendmsg\n");
	sys_close(fd);
	return 0;
}



int drain_fds(struct parasite_drain_fd *data)
{
	std_printf("nr_fds %d\n", data->nr_fds);
	int msg = sys_getpid();
	int gate = connect_gate("/local.sock2");
	sendfd(gate, 4, &msg, sizeof(msg));
	return 0;
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
	int ret = 0;

	sys_write(1, st, 15); 

	tsock = sys_socket(PF_UNIX, SOCK_SEQPACKET, 0);
	if(tsock < 0){
		st[4] = 'O';
		sys_write(1, st, 15);
	}

	std_printf("path %s, family %d\n", args->h_addr.sun_path, args->h_addr.sun_family);
	if(sys_connect(tsock, (struct sockaddr *)&args->h_addr, args->h_addr_len) < 0){
		std_printf("no connect\n");
		return 1;
	}

	__parasite_daemon_reply_ack(PARASITE_CMD_INIT_DAEMON, 0);


	/* 
	 * waiting receive command from CRIU
	 * If getting command is PARASITE_CMD_FINI, closing and cure
	 */
	while(1){
		__parasite_daemon_wait_msg(&m);
		std_printf("local msg: %d\n", m.cmd);

		if(m.cmd == PARASITE_CMD_FINI){
			fini();
			break;
		}

		switch(m.cmd){
			case PARASITE_CMD_GET_PID:
				ret = sys_getpid();
				std_printf("my pid: %d\n", ret);
				hp(data);

				break;
			case PARASITE_CMD_DRAIN_FDS:
				std_printf("drain\n");
				drain_fds(data);
				break;
		}
		__parasite_daemon_reply_ack(m.cmd, ret); 
	}
	std_printf("breaked\n");

	return 0;
}
