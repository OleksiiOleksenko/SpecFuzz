.include "common/header.S"

.macro TEST_ROLLBACK id
    PREPARE_CORRUPTION_TEST \id 42
    CALL_RTL_FUNCTION specfuzz_chkp
    jmp 2f // normal
    jmp 1f // simulation

    1:
    // introduce some state corruption
    movq $41, %rdi
    callq set_state

    // rollback
    movq $-1, instruction_counter
    CALL_RTL_FUNCTION specfuzz_rlbk_if_done
    jmp .unreachable

    2:
    EXECUTE_CORRUPTION_TEST 42
.endm

.macro TEST_NO_ROLLBACK id
    PREPARE_CORRUPTION_TEST \id 42
    CALL_RTL_FUNCTION specfuzz_chkp
    jmp 2f // normal
    jmp 1f // simulation

    1:
    jmp .unreachable

    2:
    movq $41, %rdi
    callq set_state

    // rollback
    movq $-1, instruction_counter
    CALL_RTL_FUNCTION specfuzz_rlbk_if_done
    EXECUTE_CORRUPTION_TEST 41

.endm

.data
error_unreachable:      .string     "Unreachable location\n"

.text
.globl	main
.type	main, @function
main:
    RESET_META

    # default behavior
    TEST_ROLLBACK 1

    movq $1, disable_speculation
    TEST_NO_ROLLBACK 2

    movq $0, %rax
    ret

.unreachable:
    xor %rdi, %rdi
    movl $error_unreachable, %edi
    movq $0, %rax
    call printf
    movq $1, %rax
    ret