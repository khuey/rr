#ifndef RAW_SYSCALL_FUNCTION
#error must define RAW_SYSCALL_FUNCTION before including this file
#endif

#if defined(__i386__)
        .text
        .globl RAW_SYSCALL_FUNCTION
        .hidden RAW_SYSCALL_FUNCTION
        .type RAW_SYSCALL_FUNCTION, @function
RAW_SYSCALL_FUNCTION:     /* syscallno = 4(%esp) */
        .cfi_startproc
        pushl %ebx        /* syscallno = 8(%esp) */
        .cfi_adjust_cfa_offset 4
        .cfi_rel_offset %ebx, 0
        pushl %esi        /* syscallno = 12(%esp) */
        .cfi_adjust_cfa_offset 4
        .cfi_rel_offset %esi, 0
        pushl %edi        /* syscallno = 16(%esp) */
        .cfi_adjust_cfa_offset 4
        .cfi_rel_offset %edi, 0
        pushl %ebp        /* syscallno = 20(%esp) */
        .cfi_adjust_cfa_offset 4
        .cfi_rel_offset %ebp, 0

        movl 20(%esp), %eax /* %eax = syscallno */
        movl 24(%esp), %ebx /* %ebx = a0 */
        movl 28(%esp), %ecx /* %ecx = a1 */
        movl 32(%esp), %edx /* %edx = a2 */
        movl 36(%esp), %esi /* %esi = a3 */
        movl 40(%esp), %edi /* %edi = a4 */
        movl 44(%esp), %ebp /* %ebp = a5 */

        call *48(%esp)

        popl %ebp
        .cfi_adjust_cfa_offset -4
        .cfi_restore %ebp
        popl %edi
        .cfi_adjust_cfa_offset -4
        .cfi_restore %edi
        popl %esi
        .cfi_adjust_cfa_offset -4
        .cfi_restore %esi
        popl %ebx
        .cfi_adjust_cfa_offset -4
        .cfi_restore %ebx
        ret
        .cfi_endproc
        .size RAW_SYSCALL_FUNCTION, . - RAW_SYSCALL_FUNCTION

#elif defined(__x86_64__)
        .text
        .globl RAW_SYSCALL_FUNCTION
        .hidden RAW_SYSCALL_FUNCTION
        .type RAW_SYSCALL_FUNCTION, @function
RAW_SYSCALL_FUNCTION:
	/* Incoming args are in %rdi, %rsi, %rdx, %rcx, %r8, %r9, and 8(%rsp).
	   Syscall arguments are %rdi, %rsi, %rdx, %r10, %r8, %r9. */
	movq %rdi, %rax         /* syscall number */
	movq %rsi, %rdi         /* first syscall arg */
	movq %rdx, %rsi         /* second syscall arg */
	movq %rcx, %rdx         /* third syscall arg */
	movq %r8, %r10          /* fourth syscall arg */
	movq %r9, %r8           /* fifth syscall arg */
	movq 8(%rsp), %r9       /* sixth syscall arg */

	callq *16(%rsp)

        ret
	.size RAW_SYSCALL_FUNCTION, . - RAW_SYSCALL_FUNCTION
#elif defined(__arm__)
	.text
	.globl RAW_SYSCALL_FUNCTION
	.hidden RAW_SYSCALL_FUNCTION
	.type RAW_SYSCALL_FUNCTION, %function
RAW_SYSCALL_FUNCTION:
	/* Incoming syscall no is in r0, args 1-3 in r1-3, 4-6 on the stack
	   Syscall args go in r0-r5, syscallno in r7*/
	push {r4, r5, r6, r7, lr}	/* ABI says r0-r3 are not preserved,
					   but r4-r7 are */
	mov r7, r0 			/* syscall number */
	mov r0, r1			/* first syscall arg */
	mov r1, r2			/* second syscall arg */
	mov r2, r3			/* third syscall arg */
	mov r6, sp
	add r6, #20			/* do stack math to skip past what we
					   saved to the remaining parameters */
	ldmia r6, {r3, r4, r5, r6}	/* fourth, fifth, and sixth syscall
					   args, and traced_syscall_ip */
	blx r6
	pop {r4, r5, r6, r7, pc}
	.size RAW_SYSCALL_FUNCTION, . - RAW_SYSCALL_FUNCTION
#else
#error unknown CPU architecture
#endif /* __i386__/__x86_64__ */
#if defined(__arm__)
        .section .note.GNU-stack,"",%progbits
#else
        .section .note.GNU-stack,"",@progbits
#endif
        .previous
