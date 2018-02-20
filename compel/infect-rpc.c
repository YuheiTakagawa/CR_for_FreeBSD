//#include "log.h"
//#include "common/bug.h"
#include "xmalloc.h"
//#include "common/lock.h"

#include "infect.h"
#include "infect-priv.h"
#include "infect-rpc.h"
#include "rpc-pie-priv.h"

static int __parasite_send_cmd(int sockfd, struct ctl_msg *m)
{
	int ret;


	ret = send(sockfd, m, sizeof(*m), 0);
	if (ret == -1) {
		return -1;
	} else if (ret != sizeof(*m)) {
		return -1;
	}

	return 0;
}

int parasite_wait_ack(int sockfd, unsigned int cmd, struct ctl_msg *m)
{
	int ret;

	while (1) {
		memzero(m, sizeof(*m));

		ret = recv(sockfd, m, sizeof(*m), MSG_WAITALL);
		if (ret == -1) {
			return -1;
		} else if (ret != sizeof(*m)) {
			return -1;
		}

		if (m->cmd != cmd || m->ack != cmd) {
			return -1;
		}
		return 0;
	}

	return -1;
}

int compel_rpc_sync(unsigned int cmd, struct parasite_ctl *ctl)
{
	struct ctl_msg m;

	if (parasite_wait_ack(ctl->tsock, cmd, &m))
		return -1;

	if (m.err != 0) {
		return -1;
	}

	return 0;
}

int compel_rpc_call(unsigned int cmd, struct parasite_ctl *ctl)
{
	struct ctl_msg m;

	m = ctl_msg_cmd(cmd);
	return __parasite_send_cmd(ctl->tsock, &m);
}

int compel_rpc_call_sync(unsigned int cmd, struct parasite_ctl *ctl)
{
	int ret;

	ret = compel_rpc_call(cmd, ctl);
	if (!ret)
		ret = compel_rpc_sync(cmd, ctl);

	return ret;
}

int compel_rpc_sock(struct parasite_ctl *ctl)
{
	return ctl->tsock;
}

