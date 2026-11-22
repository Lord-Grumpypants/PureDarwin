.section __TEXT,__text,regular,pure_instructions

.macro SYSCALL name, number
.globl _pd_sys_\name
_pd_sys_\name:
    movq $(0x02000000 + \number), %rax
    syscall
    jc 1f
    ret
1:
    negq %rax
    ret
.endm

SYSCALL open,  5
SYSCALL close, 6
SYSCALL read,  3
SYSCALL write, 4
