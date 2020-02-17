.extern set_state
.extern store_stack_state
.extern check_state
.extern specfuzz_chkp
.extern current_rsp
.extern log_test_start
.extern log_test_end

.macro LOG msg
    movl    $\msg, %edi
    xorl    %eax, %eax
    callq   printf
.endm

.macro RESET_META
    movq $0, disable_speculation
    movq $0, nesting_level
    movq $specfuzz_call_type_stack, specfuzz_call_type_stack_sp
    movq $0, instruction_counter
.endm

.macro PREPARE_CORRUPTION_TEST id value
    movq $\id, %rsi
    LOG log_test_start
    movq $\value, %rdi
    callq set_state
    callq store_stack_state
.endm

.macro EXECUTE_CORRUPTION_TEST value
    movq $\value, %rdi
    callq check_state
    cmp $0, %rax
    je 1f
        ret
    1:
    RESET_META
    LOG log_test_end
.endm

.macro CALL_RTL_FUNCTION fn_name
    movq %rsp, current_rsp
    leaq specfuzz_rtl_frame, %rsp
    callq \fn_name
    movq current_rsp, %rsp
.endm

.data
log_test_start:     .asciz     "Running test No. %d: "
log_test_end:       .asciz      "ok\n"
