#ifndef __EMULATE__
#define __EMULATE__

/*
 * MAP_ANONYMOUS on FreeBSD is 0x200,
 * but MAP_ANONYMOUS on Linux is 0x20.
 * To inject unique code to Linux process
 * which running on FreeBSD with Linuxulator.
 */
#define LINUX_MAP_ANONYMOUS 0x20
#define LINUX_MAP_GROWDOWN 0x100

/*
 * It is different between Linux register
 * struct(struct user_regs_struct) and
 * FreeBSD register struct(struct reg).
 * (member size, member row)
 */

struct linuxreg{
	unsigned long int r15;
	unsigned long int r14;
        unsigned long int r13;
        unsigned long int r12;
        unsigned long int rbp;
        unsigned long int rbx;
        unsigned long int r11;
        unsigned long int r10;
        unsigned long int r9;
        unsigned long int r8;
        unsigned long int rax;
        unsigned long int rcx;
        unsigned long int rdx;
        unsigned long int rsi;
        unsigned long int rdi;
        unsigned long int orig_rax;
        unsigned long int rip;
        unsigned long int cs;
        unsigned long int eflags;
        unsigned long int rsp;
        unsigned long int ss;
        unsigned long int fs_base;
        unsigned long int gs_base;
        unsigned long int ds;
        unsigned long int es;
        unsigned long int fs;
        unsigned long int gs;
};


#endif
