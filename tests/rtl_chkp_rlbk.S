.data
error_unreachable:      .string     "Unreachable control flow\n"

.text
.globl	test
.type	test, @function
test:
    movq $42, %rdi
    callq set_state
    callq store_stack_state

    // immitate SF instrumentation
    movq %rsp, current_rsp
    leaq specfuzz_rtl_frame, %rsp
    callq specfuzz_chkp
    movq current_rsp, %rsp
    jmp .normal
    jmp .simulation

    .simulation:
    // introduce some state corruption
    movq $41, %rdi
    callq set_state

    // rollback
    movq $-1, instruction_counter

    movq %rsp, current_rsp
    leaq specfuzz_rtl_frame, %rsp
    callq specfuzz_rlbk_if_done
    jmp .unreachable

    .normal:
    movq $42, %rdi
    callq check_state
    ret

    .unreachable:
    xor %rdi, %rdi
    movl $error_unreachable, %edi
    movq $0, %rax
    call printf
    movq $1, %rax
    ret