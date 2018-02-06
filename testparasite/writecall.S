.data
msg: .ascii "Hello World\n"

.text
.global _start

_start:
movq $57, %rax
syscall
int3
movq %rax, %rdi
#movq $1, %rax
#movq $1, %rdi
#movq 13(%rip), %rsi
#movq $12, %rdx
#syscall
#int3
#movq %rax, %rdi
#movq $60, %rax
#movq $0, %rdi
#syscall
