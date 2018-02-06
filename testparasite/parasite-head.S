.section .head.text, "ax"

.macro PARASITE_ENTRY num
	subq	$16, %rsp
	andq	$~15, %rsp
	pushq	$\num
	movq	%rsp, %rbp
	call	parasite_service
.endm
