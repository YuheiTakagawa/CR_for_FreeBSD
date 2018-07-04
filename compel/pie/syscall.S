#include "syscall-x86.S"

SYSCALL(sys_read, 0)
SYSCALL(sys_write, 1)
SYSCALL(sys_close, 3)
SYSCALL(sys_sendmsg, 46)
SYSCALL(sys_recvmsg, 47)
SYSCALL(sys_getpid, 39)
SYSCALL(sys_socket, 41)
SYSCALL(sys_connect, 42)
SYSCALL(sys_sendto, 44)
SYSCALL(sys_recvfrom, 45)
SYSCALL(sys_exit, 60)
