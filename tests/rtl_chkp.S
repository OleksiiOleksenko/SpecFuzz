.extern set_state
.extern store_stack_state
.extern check_state
.extern specfuzz_chkp
.extern current_rsp

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
    jmp .dummy
    .dummy:

    movq $42, %rdi
    callq check_state
    ret
