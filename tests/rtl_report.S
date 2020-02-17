.include "common/header.S"

.macro CORRUPTION_TEST_FOR_REPORT value
    pushq $0x256
    popfq
    movq $\value, %rsi

    movq $\value, %rdi
    callq check_state
    cmp $0, %rax
    je 1f
        ret
    1:
    LOG log_test_end
.endm

.macro TEST id
    PREPARE_CORRUPTION_TEST \id 41
    CALL_RTL_FUNCTION specfuzz_report
    CORRUPTION_TEST_FOR_REPORT 41
.endm

.data
error_unreachable:      .string     "Unreachable location\n"

.text
.globl	main
.p2align        4, 0x90
.type	main, @function
main:
    callq specfuzz_init
    RESET_META
    movq $42, %rdi
    callq set_state
    callq store_stack_state
    CALL_RTL_FUNCTION specfuzz_chkp
    jmp .L1 // normal
    jmp .L2 // simulation

    .L1:
    EXECUTE_CORRUPTION_TEST 42 0

    movq $0, %rax
    ret

    .L2:
    // report
    TEST 1
    TEST 2 // make sure we can call the report repeatedly

    // rollback
    movq $-1, instruction_counter
    CALL_RTL_FUNCTION specfuzz_rlbk_if_done
    jmp .unreachable


.unreachable:
    xor %rdi, %rdi
    movl $error_unreachable, %edi
    movq $0, %rax
    call printf
    movq $1, %rax
    ret

