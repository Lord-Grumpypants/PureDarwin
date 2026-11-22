.section __TEXT,__text,regular,pure_instructions
.globl _pd_start
.extern _pd_init_main

_pd_start:
    movq %rsp, %rdi
    andq $-16, %rsp
    call _pd_init_main

1:
    ud2
    jmp 1b
