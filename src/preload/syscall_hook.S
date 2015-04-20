#if defined(__i386__)
/**
 * Jump to this hook from |__kernel_vsyscall()|, to buffer syscalls that
 * we otherwise couldn't wrap through LD_PRELOAD helpers.  Return the
 * *RAW* kernel return value, not the -1/errno mandated by POSIX.
 *
 * Remember, this function runs *below* the level of libc.  libc can't
 * know that its call to |__kernel_vsyscall()| has been re-routed to
 * us.
 */
        .text
        .global _syscall_hook_trampoline
        .hidden _syscall_hook_trampoline
        .type _syscall_hook_trampoline, @function
_syscall_hook_trampoline:
        .cfi_startproc

        /* Build a |struct syscall_info| by pushing all the syscall
         * args and the number onto the stack. */
                          /* struct syscall_info info; */
        pushl %ebp        /* info.args[5] = $ebp; */
        .cfi_adjust_cfa_offset 4
        .cfi_rel_offset %ebp, 0
        pushl %edi        /* info.args[4] = $edi; */
        .cfi_adjust_cfa_offset 4
        .cfi_rel_offset %edi, 0
        pushl %esi        /* info.args[3] = $esi; */
        .cfi_adjust_cfa_offset 4
        .cfi_rel_offset %esi, 0
        pushl %edx        /* info.args[2] = $edx; */
        .cfi_adjust_cfa_offset 4
        .cfi_rel_offset %edx, 0
        pushl %ecx        /* info.args[1] = $ecx; */
        .cfi_adjust_cfa_offset 4
        .cfi_rel_offset %ecx, 0
        pushl %ebx        /* info.args[0] = $ebx; */
        .cfi_adjust_cfa_offset 4
        .cfi_rel_offset %ebx, 0
        pushl %eax        /* info.no = $eax; */
        .cfi_adjust_cfa_offset 4

        /* $esp points at &info.  Push that pointer on the stack as
         * our arg for vsyscall_hook(). */
        movl %esp, %ecx
        pushl %ecx
        .cfi_adjust_cfa_offset 4

        call syscall_hook
        /* $eax = vsyscall_hook(&info); */

        /* $eax is now the syscall return value.  Erase the |&info|
         * arg and |info.no| from the stack so that we can restore the
         * other registers we saved. */
        addl $8, %esp
        .cfi_adjust_cfa_offset -8

        /* Contract of __kernel_vsyscall() and real syscalls is that even
         * callee-save registers aren't touched, so we restore everything
         * here. */
        popl %ebx
        .cfi_adjust_cfa_offset -4
        .cfi_restore %ebx
        popl %ecx
        .cfi_adjust_cfa_offset -4
        .cfi_restore %ecx
        popl %edx
        .cfi_adjust_cfa_offset -4
        .cfi_restore %edx
        popl %esi
        .cfi_adjust_cfa_offset -4
        .cfi_restore %esi
        popl %edi
        .cfi_adjust_cfa_offset -4
        .cfi_restore %edi
        popl %ebp
        .cfi_adjust_cfa_offset -4
        .cfi_restore %ebp

        ret
        .cfi_endproc
        .size _syscall_hook_trampoline, .-_syscall_hook_trampoline



        .global _syscall_hook_trampoline_3d_01_f0_ff_ff
        .hidden _syscall_hook_trampoline_3d_01_f0_ff_ff
        .type _syscall_hook_trampoline_3d_01_f0_ff_ff, @function
_syscall_hook_trampoline_3d_01_f0_ff_ff:
        .cfi_startproc

        call _syscall_hook_trampoline
        cmpl $0xfffff001,%eax
        ret

        .cfi_endproc
        .size _syscall_hook_trampoline_3d_01_f0_ff_ff, .-_syscall_hook_trampoline_3d_01_f0_ff_ff



#elif defined(__x86_64__)
        .text

        .global _syscall_hook_trampoline
        .hidden _syscall_hook_trampoline
        .type _syscall_hook_trampoline, @function
        .p2align 4
_syscall_hook_trampoline:
        .cfi_startproc
        /* Build a |struct syscall_info| on the stack by pushing the arguments
           and syscall number. */
        pushq %r9
        .cfi_adjust_cfa_offset 8
        .cfi_rel_offset %r9, 0
        pushq %r8
        .cfi_adjust_cfa_offset 8
        .cfi_rel_offset %r8, 0
        pushq %r10
        .cfi_adjust_cfa_offset 8
        .cfi_rel_offset %r10, 0
        pushq %rdx
        .cfi_adjust_cfa_offset 8
        .cfi_rel_offset %rdx, 0
        pushq %rsi
        .cfi_adjust_cfa_offset 8
        .cfi_rel_offset %rsi, 0
        pushq %rdi
        .cfi_adjust_cfa_offset 8
        .cfi_rel_offset %rdi, 0
        pushq %rax
        .cfi_adjust_cfa_offset 8
        .cfi_rel_offset %rax, 0

        /* Call our hook. */
        mov %rsp, %rdi
        callq syscall_hook

        /* On entrance, we pushed the %rax, the syscall number. But we don't
           want to |pop %rax|, as that will overwrite our return value. Pop
           into %r11 instead. */
        pop %r11
        .cfi_adjust_cfa_offset -8

        /* We don't really *need* to restore these, since the kernel could have
           trashed them all anyway. But it seems reasonable to do so. */
        pop %rdi
        .cfi_adjust_cfa_offset -8
        .cfi_restore %rdi
        pop %rsi
        .cfi_adjust_cfa_offset -8
        .cfi_restore %rsi
        pop %rdx
        .cfi_adjust_cfa_offset -8
        .cfi_restore %rdx
        pop %r10
        .cfi_adjust_cfa_offset -8
        .cfi_restore %r10
        pop %r8
        .cfi_adjust_cfa_offset -8
        .cfi_restore %r8
        pop %r9
        .cfi_adjust_cfa_offset -8
        .cfi_restore %r9

        /* ...and we're done. */
        ret
        .cfi_endproc
        .size _syscall_hook_trampoline, . - _syscall_hook_trampoline



        .global _syscall_hook_trampoline_48_3d_01_f0_ff_ff
        .hidden _syscall_hook_trampoline_48_3d_01_f0_ff_ff
        .type _syscall_hook_trampoline_48_3d_01_f0_ff_ff, @function
_syscall_hook_trampoline_48_3d_01_f0_ff_ff:
        .cfi_startproc

        callq _syscall_hook_trampoline
        cmpq $0xfffffffffffff001,%rax
        ret

        .cfi_endproc
        .size _syscall_hook_trampoline_48_3d_01_f0_ff_ff, .-_syscall_hook_trampoline_48_3d_01_f0_ff_ff



        .global _syscall_hook_trampoline_48_8b_3c_24
        .hidden _syscall_hook_trampoline_48_8b_3c_24
        .type _syscall_hook_trampoline_48_8b_3c_24, @function
_syscall_hook_trampoline_48_8b_3c_24:
        .cfi_startproc

        callq _syscall_hook_trampoline
        /* The original instruction after the syscall is movq (%rsp),%rdi.
           Because we pushed a return address before reaching this point,
           to get the equivalent behavior we need to load the next word on the
           stack. */
        movq 8(%rsp),%rdi
        ret

        .cfi_endproc
        .size _syscall_hook_trampoline_48_8b_3c_24, .-_syscall_hook_trampoline_48_8b_3c_24



        .global _syscall_hook_trampoline_90_90_90
        .hidden _syscall_hook_trampoline_90_90_90
        .type _syscall_hook_trampoline_90_90_90, @function
_syscall_hook_trampoline_90_90_90:
        .cfi_startproc

        jmp _syscall_hook_trampoline

        .cfi_endproc
        .size _syscall_hook_trampoline_90_90_90, .-_syscall_hook_trampoline_90_90_90

#elif defined(__arm__)
        .global _syscall_hook_trampoline
        .hidden _syscall_hook_trampoline
        .type _syscall_hook_trampoline, %function
_syscall_hook_trampoline:
        /* Build a |struct syscall_info| by pushing all the syscall
         * args and the number onto the stack. */
                          /* struct syscall_info info; */
	push {lr}
	push {r0,r1,r2,r3,r4,r5}
	push {r7}

	mov r0, sp
	blx syscall_hook

	/* r0 now has the return value, so be careful not to destroy it. */
	mov lr, r0
	add sp, #4 /* destroy r7 */
	pop {r0, r1, r2, r3, r4, r5}
	mov r0, lr
	pop {pc}

	.size _syscall_hook_trampoline, .-_syscall_hook_trampoline

        .global _syscall_hook_trampoline_80_bc_10_f5_80_5f_38_bf_70_47_xx_fx_xx_xx
        .hidden _syscall_hook_trampoline_80_bc_10_f5_80_5f_38_bf_70_47_xx_fx_xx_xx
        .type _syscall_hook_trampoline_80_bc_10_f5_80_5f_38_bf_70_47_xx_fx_xx_xx, %function
_syscall_hook_trampoline_80_bc_10_f5_80_5f_38_bf_70_47_xx_fx_xx_xx:
	pop {r7}
	push {lr}
	bl _syscall_hook_trampoline
	/* The original instructions after the syscall were:
	     pop {r7}
	     cmn.w r0, #4096
	     it cc
	     bxcc lr
	     b.w <offset>
	   We injected
	     push {r7, lr} ; overwriting svc #0
	     ldr r7, [pc, #2]
	     blx r7
	     pop {r7}
	     b.w <offset> 	; relocated from above
	     _syscall_hook_trampoline_80_bc_10_f5_80_5f_38_bf_70_47_xx_fx_xx_xx address

	   We only need to return to the callee if the comparison fails.  If it succeeds
	   we can jump directly to the callee's callee.
	 */

	cmn r0, #4096
	/* the easy case, we don't need our return address anymore */
	popcc {lr} /* our return address */
	popcc {lr} /* callee's return address */
	popcc {r7} /* the callee pushed this */
	bxcc lr

	/* the hard case */
	pop {r7, lr} /* put our return address in r7, the callee's return address in lr */
	bx r7

	.size _syscall_hook_trampoline_80_bc_10_f5_80_5f_38_bf_70_47_xx_fx_xx_xx, .-_syscall_hook_trampoline_80_bc_10_f5_80_5f_38_bf_70_47_xx_fx_xx_xx

        .global _syscall_hook_trampoline_80_bd_af_f3_00_80_af_f3_00_80
        .hidden _syscall_hook_trampoline_80_bd_af_f3_00_80_af_f3_00_80
        .type _syscall_hook_trampoline_80_bd_af_f3_00_80_af_f3_00_80, %function
_syscall_hook_trampoline_80_bd_af_f3_00_80_af_f3_00_80:
	pop {r7}
	push {lr}
	bl _syscall_hook_trampoline
	/* The original instructions after the syscall were:
	     pop {r7, pc}
	     nop
	     nop
	   We injected
	     push {r7} ; overwriting svc #0
	     ldr r7, [pc, #1]
	     bx r7
	     nop
	     _syscall_hook_trampoline_80_bd_af_f3_00_80_af_f3_00_80 address
	 */

	pop {lr}
	pop {r7, pc}

	.size _syscall_hook_trampoline_80_bd_af_f3_00_80_af_f3_00_80, .-_syscall_hook_trampoline_80_bd_af_f3_00_80_af_f3_00_80

	.global _syscall_hook_trampoline_07_46_60_46_xx_fx_xx_cx_38_46_5d_f8_04_eb
	.hidden _syscall_hook_trampoline_07_46_60_46_xx_fx_xx_cx_38_46_5d_f8_04_eb
	.type _syscall_hook_trampoline_07_46_60_46_xx_fx_xx_cx_38_46_5d_f8_04_eb, %function
_syscall_hook_trampoline_07_46_60_46_xx_fx_xx_cx_38_46_5d_f8_04_eb:
	pop {r7}
	push {lr}
	bl _syscall_hook_trampoline
	/* The original instructions after the syscall were:
	     mov r7, r0
	     mov r0, ip
	     bl <offset>
	     mov r0, r7
	     ldr.w lr, [sp], #4
	   We injected
	     push {r7}
	     ldr r7, [pc, #0]
	     blx r7
	     _syscall_hook_trampoline_07_46_60_46_xx_fx_xx_cx_38_46_5d_f8_04_eb address
	     absolute address of the original bl
	   with a nop at either the beginning or the end to maintain alignment.
	*/

	ldr lr, [sp, #0]
	bic r7, lr, #1 /* clear the thumb bit from lr */
	add r7, r7, #4
	ldr lr, [r7]
	mov r7, r0
	mov r0, ip

	blx lr

	mov r0, r7
	pop {r7}  /* our lr */
	ldr lr, [sp], #4
	/* This either goes immediately to the next instruction, or to our
	   trailing nop we added for alignment */
	add r7, #8

	bx r7

	.size _syscall_hook_trampoline_07_46_60_46_xx_fx_xx_cx_38_46_5d_f8_04_eb, .-_syscall_hook_trampoline_07_46_60_46_xx_fx_xx_cx_38_46_5d_f8_04_eb

#endif

        .section .note.GNU-stack,"",%progbits
