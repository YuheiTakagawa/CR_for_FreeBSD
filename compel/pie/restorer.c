#include <sys/types.h>
#include <signal.h>
#include <stdint.h>

struct xsave_struct {
	union {
		uint8_t extened_state_area[3000];
	};
};
typedef struct {
	union {
		struct xsave_struct xsave;
	};
	uint8_t has_fpu;
} fpu_state_64_t;

typedef struct {
	union {
		fpu_state_64_t fpu_state_64;
	};
	uint8_t has_fpu;
} fpu_state_t;



#define ARCH_RT_SIGRETURN(new_sp, sigframe)	\
	asm volatile(			\
		"movq %0, %%rax		\n" \
		"movq %%rax, %%rsp	\n" \
		"movl $15, %%eax \n" \
		"syscall	\n" \
		:		\
		: "r"(new_sp)	\
		: "rax", "rsp","memory")

#define rt_sigcontext sigcontext

typedef struct {
	uint64_t sig[1];
} k_rtsigset_t;

typedef struct rt_siginfo {
	int si_signo;
	int si_errno;
	int si_code;
	int _pad[128];
} rt_siginfo_t;

typedef struct rt_sigaltstack {
	void * ss_sp;
	int ss_flags;
	size_t ss_size;
} rt_stack_t;

struct rt_ucontext {
	unsigned long uc_flags;
	struct rt_ucontext *uc_link;
	rt_stack_t uc_stack;
	struct rt_sigcontext uc_mcontext;
	k_rtsigset_t uc_sigmask;
	int __unused[32 - (sizeof(k_rtsigset_t) / sizeof(int))];
	unsigned long uc_regspace[128] __attribute__((aligned(8)));
};

struct rt_sigframe {
	char *pretcode;
	struct rt_ucontext uc;
	struct rt_siginfo info;
	fpu_state_t fpu_state;
};



#define RT_SIGFRAME_OFFSET(rt_sigframe) 8

static void rst_sigreturn(unsigned long new_sp,
	struct rt_sigframe *sigframe)
{
	ARCH_RT_SIGRETURN(new_sp, sigframe);
}

int __export_restore_thread(int cmd, void *args){
	unsigned long new_sp;
	struct rt_sigframe *rt_sigframe;
	rt_sigframe = (struct rt_sigframe*)args;
	new_sp = (long)rt_sigframe + RT_SIGFRAME_OFFSET(rt_sigframe);
	rst_sigreturn(new_sp, rt_sigframe);
}
