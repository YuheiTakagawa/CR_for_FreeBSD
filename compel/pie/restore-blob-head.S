/*
.data
msg: .ascii "Hello World\n"

.text
#.global _start
.global parasite_service
.type parasite_service @function
*/
#_start:
#movq $3, %rax
#movq $3, %rdi
#syscall
#int3
/*
movq %rax, %rdi
movq $1, %rax
movq $1, %rdi
movq $0x8006c9000, %rsi
movq $20, %rdx
syscall
call parasite_service
movq %rax, %r10
movq $8, %rax
movq $3, %rdi
movq %r10, %rsi
movq $0, %rdx
syscall
int3
*/
#include "linkage.h"
	.section .head.text, "ax"

.macro PARASITE_ENTRY num
	subq $16, %rsp
	andq $~15, %rsp
	pushq $\num
	movq %rsp, %rbp
	movl __export_parasite_cmd(%rip), %edi
	leaq __export_parasite_args(%rip), %rsi
	call __export_restore_thread
.endm

ENTRY(__export_parasite_head_start)
	PARASITE_ENTRY 0
	int3
END(__export_parasite_head_start)

.align 8
GLOBAL(__export_parasite_cmd)
	.long 0
#movq %rax, %rdi
#movq $60, %rax
#movq $0, %rdi
#syscall
