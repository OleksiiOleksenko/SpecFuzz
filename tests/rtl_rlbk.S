.include "common/header.S"

.macro TEST id fn_name
    PREPARE_CORRUPTION_TEST \id 42
    CALL_RTL_FUNCTION \fn_name
    EXECUTE_CORRUPTION_TEST 42 1
.endm

.text
.globl	main
.p2align        4, 0x90
.type	main, @function
main:
    RESET_META
    movq $0, nesting_level
    TEST 1 specfuzz_rlbk_if_done

    movq $1, nesting_level
    movq $10, instruction_counter
    TEST 2 specfuzz_rlbk_if_done

    movq $0, nesting_level
    TEST 3 specfuzz_rlbk_forced

    movq $0, nesting_level
    TEST 4 specfuzz_rlbk_external_call

    movq $0, nesting_level
    TEST 5 specfuzz_rlbk_indirect_call

    movq $0, nesting_level
    TEST 6 specfuzz_rlbk_serializing

    movq $0, nesting_level
    TEST 7 specfuzz_rlbk_patched

    movq $0, %rax
    ret
