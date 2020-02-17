.data

.extern printf

.set EFLAGS_VALUE, 0x256

.globl previous_rsp
.globl previous_rbp
previous_rsp:                   .quad       0
previous_rbp:                   .quad       0

.globl previous_instruction_counter
.globl previous_nesting_level
.globl previous_disable_speculation
.globl previous_specfuzz_call_type_stack_sp
previous_instruction_counter:           .quad 0
previous_nesting_level:                 .quad 0
previous_disable_speculation:           .quad 0
previous_specfuzz_call_type_stack_sp:   .quad 0

.globl fx_frame
.align 64
fx_frame:                       .zero       512

corruption_id:                  .quad       0
error_corruption:               .string     "Corrupted state with id %d. See process_state.S:check_state() for details\n"

// -----------------------------------------
.text
/// set_state: Sets all GPRs to the same value
/// rdi: the value
///
.globl	set_state
.type	set_state, @function
set_state:
    // - FPU and SIMD states
    movq $0, %rax
    .L1: cmpq $512, %rax
    je .L2
        movq %rdi, fx_frame(%rax)
        addq $8, %rax
        jmp .L1
    .L2:
    fxrstor64 fx_frame

    // GPRs
    movq %rdi, %rax
    movq %rdi, %rbx
    movq %rdi, %rcx
    movq %rdi, %rdx
    movq %rdi, %rsi
    movq %rdi, %r8
    movq %rdi, %r9
    movq %rdi, %r10
    movq %rdi, %r11
    movq %rdi, %r12
    movq %rdi, %r13
    movq %rdi, %r14
    movq %rdi, %r15

    // Flags
    pushq $EFLAGS_VALUE
    popfq
    ret

.globl	store_stack_state
.type	store_stack_state, @function
store_stack_state:
    movq %rsp, previous_rsp
    movq %rbp, previous_rbp
    ret

.globl	store_metadata
.type	store_metadata, @function
store_metadata:
    pushq %rax
    movq instruction_counter, %rax
    movq %rax, previous_instruction_counter
    movq nesting_level, %rax
    movq %rax, previous_nesting_level
    movq disable_speculation, %rax
    movq %rax, previous_disable_speculation
    movq specfuzz_call_type_stack_sp, %rax
    movq %rax, previous_specfuzz_call_type_stack_sp
    popq %rax
    ret


/// check_state: Check if all GPR values match the value in the argument
/// rdi: the value
///
.globl	check_state
.type	check_state, @function
check_state:
.macro CHECK_VALUE id, register, value
    movq \id, corruption_id
    cmp \register, \value
    jne check_state.fail
.endm

    // Flags
    pushfq
    cmpq $EFLAGS_VALUE, (%rsp)
    je .L5
        popfq
        movq $0, corruption_id
        jmp check_state.fail
    .L5: popfq

    // stack
    CHECK_VALUE $1,  %rsp, previous_rsp
    CHECK_VALUE $2,  %rbp, previous_rbp

    // GPRs
    CHECK_VALUE $3,  %rdi, %rax
    CHECK_VALUE $4,  %rdi, %rbx
    CHECK_VALUE $5,  %rdi, %rcx
    CHECK_VALUE $6,  %rdi, %rdx
    CHECK_VALUE $7,  %rdi, %rsi
    CHECK_VALUE $8,  %rdi, %r8
    CHECK_VALUE $9,  %rdi, %r9
    CHECK_VALUE $10, %rdi, %r10
    CHECK_VALUE $11, %rdi, %r11
    CHECK_VALUE $12, %rdi, %r12
    CHECK_VALUE $13, %rdi, %r13
    CHECK_VALUE $14, %rdi, %r14
    CHECK_VALUE $15, %rdi, %r15

    // FPU
    // TODO: this code does not work - sometimes fxsave64 introduces random corruptions
    // needs further investigation
    //fxsave64 fx_frame
    //movq $0, %rax
    //.L3: addq $8, %rax   // skip the first element, it's always corrupted
    //cmpq $512, %rax
    //je .L4
    //    cmpq $24, %rax  // 3rd element also always gets corrupted
    //    je .L3
    //    CHECK_VALUE $16, %rdi, fx_frame(%rax)
    //    jmp .L3
    //.L4:

check_state.success:
    movq $0, %rax
    ret

check_state.fail:
    pushq $0x246  # just in case, overwrite EFLAGS to avoid problems with printf
    popfq

    movq corruption_id, %rsi
    xor %rdi, %rdi
    movl $error_corruption, %edi
    movq $0, %rax
    call printf

    movq $1, %rax
    ret

/// Check integrity of global variables
///
.globl  check_metadata
.type	check_metadata, @function
check_metadata:
.macro CHECK_GLOBAL id, value, prev_value
    movq \id, corruption_id
    movq \prev_value, %rax
    cmp %rax, \value
    jne check_metadata.fail
.endm

    CHECK_GLOBAL $16, previous_instruction_counter, instruction_counter
    CHECK_GLOBAL $17, previous_nesting_level, nesting_level
    CHECK_GLOBAL $18, previous_disable_speculation, disable_speculation
    CHECK_GLOBAL $19, previous_specfuzz_call_type_stack_sp, specfuzz_call_type_stack_sp
    ret

check_metadata.fail:
    pushq $0x246  # just in case, overwrite EFLAGS to avoid problems with printf
    popfq

    movq corruption_id, %rsi
    xor %rdi, %rdi
    movl $error_corruption, %edi
    movq $0, %rax
    call printf

    movq $1, %rax
    ret