.include "common/header.S"

.macro TEST id
    PREPARE_CORRUPTION_TEST \id 42
    CALL_RTL_FUNCTION specfuzz_chkp
    jmp 1f  // imitate instrumentation
    1:
    EXECUTE_CORRUPTION_TEST 42 0
.endm

.macro TEST_WITH_META id
    PREPARE_CORRUPTION_TEST \id 42
    CALL_RTL_FUNCTION specfuzz_chkp
    jmp 1f  // imitate instrumentation
    1:
    EXECUTE_CORRUPTION_TEST 42 1
.endm

.text
.globl	main
.p2align        4, 0x90
.type	main, @function
main:
    RESET_META

    # default behavior
    TEST 1

    # configuration variants
    movq $1, disable_speculation
    TEST_WITH_META 2

    movq $1, nesting_level
    movq $10, instruction_counter  #  needs to be set. Otherwise, RTL will execute a rollback
    TEST 3

    movq $2, nesting_level  # larger than max_nesting_level
    movq $10, instruction_counter
    TEST 4

    movq $0, %rax
    ret
