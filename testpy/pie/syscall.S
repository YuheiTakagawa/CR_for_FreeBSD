#include "syscall-x86.S"

SYSCALL(sys_fork, 2)
SYSCALL(sys_read, 3)
SYSCALL(sys_write, 4)
SYSCALL(sys_close, 6)
SYSCALL(sys_getpid, 20)
SYSCALL(sys_nanosleep, 240)
