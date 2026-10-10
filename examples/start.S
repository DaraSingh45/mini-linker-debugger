/* Tiny hand-written entry point: no libc, no crt1.o */
    .text
    .globl  _start
    .type   _start, @function
_start:
    xorl    %ebp, %ebp          /* terminate the frame-pointer chain (for 'bt') */
    call    main                /* R_X86_64_PLT32 relocation */
    movl    %eax, %edi          /* exit status = return value of main */
    movl    $60, %eax           /* SYS_exit */
    syscall
    .size   _start, .-_start
    .section .note.GNU-stack,"",@progbits
