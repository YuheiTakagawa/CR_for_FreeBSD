.section .head.text, "ax"

.macro PARASITE_ENTRY num
	subq $16, %rsp
	andq $~15, %rsp
	pushq $\num
	mov %rsp, %rbp
	call parasite_service
.endm

.global __export_parasite_head_start;
.type __export_parasite_head_start, @function;
.align 4, 0x90
__export_parasite_head_start:
	PARASITE_ENTRY 0
	int $0x03
	.size __export_parasite_head_start, . - __export_parasite_head_start

.align 8
.global __export_parasite_cmd;
__export_parasite_cmd:
	.long 0
