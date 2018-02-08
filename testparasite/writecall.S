.data
msg: .ascii "Hello World\n"

.text
.global _start
.global parasite_service
.type parasite_service @function

_start:
#movq $3, %rax
#movq $3, %rdi
#syscall
#int3
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
#movq %rax, %rdi
#movq $60, %rax
#movq $0, %rdi
#syscall
