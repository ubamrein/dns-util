.globl _main
_main:
xor %rbx, %rbx                 # push the zero terminating C string to the stack
pushq %rbx
movq $0x0a21646c72, %rax
pushq %rax
movq $0x6f77206f6c6c6548, %rax
pushq %rax
movl $0x2000004, %eax           # 4 == write syscall
movl $1, %edi                   # 1 == STDOUT file descriptor
leaq (%rsp), %rsi               # string to print
movq $14, %rdx                  # size of string
syscall

popq %rax
popq %rax
popq %rax

movl $0x2000001, %eax           # exit 0
ret