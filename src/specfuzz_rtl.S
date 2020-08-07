//===-------- specfuzz_rtl.S ------------------------------------------------===//
//
// Copyright: This file is distributed under the GPL version 3 License.
// See LICENSE for details.
//
//===------------------------------------------------------------------------===//
/// \file
///
/// A runtime library that implements the more heavy-weight functionality of
///   the SpecFuzz pass: checkpoint+rollback and reporting of the detected
///   vulnerabilities.
///   Also, some helper functions.
///
/// In the file, the following abbreviations are used:
///   * flags: May clobber EFLAGS
///   * stack: May modify data on stack
///   * spec: May be executed speculatively
//===------------------------------------------------------------------------===//
.file	"specfuzz_rtl.S"

.extern printf
.extern fprintf
.extern stderr
.extern specfuzz_cov_trace_pc
.extern specfuzz_cov_vuln

.set CHECKPOINT_STACK_SIZE, (4096 * 25)
.set SPECULATION_WINDOW, 250
#ifndef MAX_NESTING_LEVEL
.set MAX_NESTING_LEVEL, 1
#endif

.macro STAT_INCREMENT var
#if ENABLE_STATS == 1
    pushfq
    incq \var
    popfq
#endif
.endm

.macro ASSERT lh cond rh error_callback
#if ENABLE_SANITY_CHECKS == 1
    cmpq \rh , \lh
    \cond \error_callback
#endif
.endm


//===------------------------------------------------------------------------===//
// Global variables
//===------------------------------------------------------------------------===//
.data

// For better cache locality, we try to keep all small variables on one or two cache lines
// and all checkpointed values on the same page
.align 4096

// Instruction counter: counts instructions executed during a simulation
.globl instruction_counter
instruction_counter:    .quad   0

// Flag indicating if we are currently in a simulation
.globl nesting_level
nesting_level:          .quad   0

// [Prioritized simulation] The maximum order of simulation for the current branch
max_nesting_level:      .quad   1

// Flag that globally disables simulation. Set, for example, when calling non-instrumented
// functions
.globl disable_speculation
disable_speculation:    .quad   0

// The stack pointer value before we called the runtime
.globl current_rsp
current_rsp:            .quad   0

// A variable for passing the results of specfuzz_cov_trace_pc to the rtl; We need it because
// of a bug in LLVM that corrupt the return value of the functions even if
// preserve_most attribute is set
.globl branch_execution_count
branch_execution_count: .quad   0

// Temporary storage for the registers used in SpecFuzz instrumentation and in the rtl
.globl tmp_gpr1
.globl tmp_gpr2
tmp_gpr1:                   .quad   0
tmp_gpr2:                   .quad   0
tmp_eflags:                 .quad   0
return_address:             .quad   0
simulation_start_address:   .quad   0

// HERE, TOTAL LENGTH: 88 bytes

// Nevermind it. The cannary is for debugging
.globl cannary
cannary: .quad 0

// A stack of state checkpoints
// Every frame contains all data necessary for rolling back to a checkpoint.
.align 64
.globl checkpoint_stack_bottom
.globl checkpoint_stack
.globl checkpoint_sp
.globl store_log_bp
checkpoint_stack_bottom:     .zero   CHECKPOINT_STACK_SIZE
checkpoint_stack:            .quad   0
checkpoint_sp:               .quad   checkpoint_stack
store_log_bp:                .quad   0    // base pointer of the Store Log

// Layout of a checkpoint
.set CHECKPOINT_STACK_REG_OFFSET,     (512 + 8)  // 8 is padding
.set CHECKPOINT_STACK_CTYPE_OFFSET,   (CHECKPOINT_STACK_REG_OFFSET + 120)
.set CHECKPOINT_STACK_DISABLE_OFFSET, (CHECKPOINT_STACK_CTYPE_OFFSET + 8)
.set CHECKPOINT_STACK_NESTING_OFFSET, (CHECKPOINT_STACK_DISABLE_OFFSET + 8)
.set CHECKPOINT_STACK_COUNTER_OFFSET, (CHECKPOINT_STACK_NESTING_OFFSET + 8)
.set CHECKPOINT_STACK_SP_OFFSET,      (CHECKPOINT_STACK_COUNTER_OFFSET + 8)
.set CHECKPOINT_STACK_PC_OFFSET,      (CHECKPOINT_STACK_SP_OFFSET + 8)
.set CHECKPOINT_STACK_FLAGS_OFFSET,   (CHECKPOINT_STACK_PC_OFFSET + 8)
.set CHECKPOINT_STACK_BP_OFFSET,      (CHECKPOINT_STACK_FLAGS_OFFSET + 8)


// Indirect call type stack
// Before every indirect call, we push the callee type on it
.globl specfuzz_call_type_stack_bottom
.globl specfuzz_call_type_stack
.globl specfuzz_call_type_stack_sp
specfuzz_call_type_stack_bottom:    .zero   4080  // allocate 1 page for the stack
specfuzz_call_type_stack:           .quad   0     // top of the stack
specfuzz_call_type_stack_sp:        .quad   specfuzz_call_type_stack // stack pointer


// A disjoint stack frame used by the runtime functions
// We use it to avoid accidental clobbering of the application stack
.align 4096
.globl specfuzz_rtl_frame
.globl specfuzz_rtl_frame_bottom
specfuzz_rtl_frame_bottom:      .zero   4088
specfuzz_rtl_frame:             .quad   0

// A disjoint stack frame for ASan functions
.globl asan_rtl_frame
.globl asan_rtl_frame_bottom
asan_rtl_frame_bottom:          .zero   4088
asan_rtl_frame:                 .quad   0

// Error messages
error_checkpoint_stack_overflow:    .string     "[SF] Error: overflow of Checkpoint Stack\n"
error_branch_table_overflow:        .string     "[SF] Error: too many Branch Table collisions\n"
asan_detected_real_overflow:        .string     "[SF] Error: That was a real, non-speculative overflow\n"
error_corrupted_nesting:            .string     "[SF] Error: nesting_level is corrupted (negative)\n"
error_not_speculative:              .string     "[SF] Error: Corrupted state outside simulation\n"

// Detected speculative faults
// Format: [SF], Falut Type, Instruction, Address, Offset, Mispredicted Branches
asan_detected_overflow_base:        .string     "[SF], 1, 0x%llx, 0x%lx, %d, 0x%lx"
asan_detected_overflow_next:        .string     ", 0x%lx"

detected_corrupted_code_pointer:    .string     "[SF], 2, 0x%llx, 0x%lx, %d, 0x%lx\n"

// Runtime statistics
.globl stat_max_depth
.globl stat_forced_external_call
.globl stat_forced_indirect_call
.globl stat_forced_serializing_instruction
.globl stat_forced_patched
.globl stat_asan_overflow
.globl stat_signal_overflow
.globl stat_corrupted_code_pointer
.globl stat_signal_misc
.globl stat_max_nesting
.globl stat_simulation_disables
.globl stat_skiped_due_to_disabled
stat_max_depth:                         .quad   0
stat_forced_external_call:              .quad   0
stat_forced_indirect_call:              .quad   0
stat_forced_serializing_instruction:    .quad   0
stat_forced_patched:                    .quad   0
stat_asan_overflow:                     .quad   0
stat_signal_overflow:                   .quad   0
stat_corrupted_code_pointer:            .quad   0
stat_signal_misc:                       .quad   0
stat_max_nesting:                       .quad   0
stat_simulation_disables:               .quad   0
stat_skiped_due_to_disabled:            .quad   0

#if PRINT_ROLLABACK_STATS != 0
first_mispredicted_branch:              .quad   0
simulation_id:                          .quad   0
debug_rollback_depth:                   .string     "[SF] rlbk: 0x%llx %lld %lld %lld\n"
#endif

//===------------------------------------------------------------------------===//
// Checkpoint and rollback
//===------------------------------------------------------------------------===//
.text

/// specfuzz_chkp: Make a checkpoint
/// Stores:
///   * current values in CPU registers
///   * EFLAGS
///   * rollback address
///   * stack pointer
///
/// CLOB: spec
.globl	specfuzz_chkp
.type	specfuzz_chkp, @function
specfuzz_chkp:
    push %r15
    movq %r15, tmp_gpr1

    // EFLAGS will get corrupted soon, so preserve it in tmp_eflags
    pushfq
    xorq %r15, %r15
    movq (%rsp), %r15
    movq %r15, tmp_eflags

    // do not start a simulation if it is globally disabled
    cmpq $0, disable_speculation
    jg specfuzz_chkp.disabled_simulation

    // check if it's time to rollback
    call specfuzz_rlbk_if_done
    ASSERT nesting_level jl $0 specfuzz_exit_corrupted_nesting_level

    // do not start a new simulation if we've reached the max nesting depth
#if ENABLE_PRIORITIZED_SIMULATION == 1
    movq max_nesting_level, %r15
    cmpq %r15, nesting_level
#else
    cmpq $MAX_NESTING_LEVEL, nesting_level
#endif
    jge specfuzz_chkp.no_simulation

    specfuzz_chkp.start_simulation:
        // Save the return address
        movq 16(%rsp), %r15
        mov %r15, return_address

        // Entering a new simulation:
        // (i.e., we're not within a nested simulation)
        cmpq $0, nesting_level
        jne .L8
            // Fixup stack_sp if it was modified outside speculation
            movq $checkpoint_stack, checkpoint_sp

            // Initialize the instruction countdown
            movq $SPECULATION_WINDOW, instruction_counter

#if PRINT_ROLLABACK_STATS != 0
            movq %r15, first_mispredicted_branch
            incq simulation_id
#endif

#if ENABLE_COVERAGE == 1
            pushq %rdi
            pushq %r11
            movq %r15, %rdi
            callq specfuzz_cov_trace_pc
#if ENABLE_PRIORITIZED_SIMULATION == 1
            # every Nth run executes up to order log4(N) + 1
            cmpq $0, branch_execution_count
            je .L10
                tzcntq branch_execution_count, %r11  // Increases every power of 4
                shrq $1, %r11
                addq $1, %r11                        // Default order: 1
                movq %r11, max_nesting_level
                jmp .L11
            .L10:
                movq $1, max_nesting_level
            .L11:
#endif  // ENABLE_PRIORITIZED_SIMULATION
            popq %r11
            popq %rdi
#endif  // ENABLE_COVERAGE
        .L8:

        // Get the current stack frame
        movq checkpoint_sp, %rsp
        ASSERT %rsp jle $checkpoint_stack_bottom specfuzz_exit_state_overflow

#if ENABLE_SEQUENTIAL_SIMULATION == 1
        // Mark that are one level deeper into nesting
        addq $1, nesting_level
#endif

        // Take a checkpoint:
        // - Preserve the previous base pointer of the Store Log, for nested rollbacks
        pushq store_log_bp

        // - The original value of eflags
        pushq tmp_eflags

        // - The address where we will continue execution after simulating misprediction
        pushq return_address

        // - Store stack pointer
        pushq current_rsp

        // - Metadata
        pushq instruction_counter
        pushq nesting_level
        pushq disable_speculation
        pushq specfuzz_call_type_stack_sp

        // - Store registers
        pushq %rax
        pushq %rbx
        pushq %rcx
        pushq %rdx
        pushq %rsi
        pushq %rdi
        pushq %rbp
        pushq %r8
        pushq %r9
        pushq %r10
        pushq %r11
        pushq %r12
        pushq %r13
        pushq %r14
        pushq tmp_gpr1

        // - FPU and SIMD states
        subq $8, %rsp  // alignment
        subq $512, %rsp
        fxsave64 (%rsp)

        movq %rsp, store_log_bp
        movq %rsp, checkpoint_sp

#if ENABLE_SEQUENTIAL_SIMULATION != 1
        // Mark that we got one level deeper into nesting
        addq $1, nesting_level
#endif

        // - Checkpoint is finished
        // Now, prepare for a simulation

        // To trigger the simulation, we have to skip a few instructions and return into the
        // simulated mispredicted branch (see SpecFuzzPass.cpp for details)
        movq return_address, %r15
        addq $0xa, %r15     // 0xa is the size of this skipped instruction
        movq %r15, simulation_start_address

        // Switch back to the RTL stack frame and restore corrupted register values
        movq $specfuzz_rtl_frame, %rsp
        subq $24, %rsp
        popfq
        popq %r15

        // Switch to the application stack
        // Note: Normally, the pass takes care of it. However, since we're not returning into
        // the next instruction, we'll also skip  the restoration to the application stack.
        // Thus, we have to do it here
        movq current_rsp, %rsp

        // Return
        jmpq *simulation_start_address

specfuzz_chkp.no_simulation:
    popfq
    popq %r15
    ret

specfuzz_chkp.disabled_simulation:
    ASSERT checkpoint_sp jle $checkpoint_stack_bottom specfuzz_exit_state_overflow
    movq $checkpoint_stack, checkpoint_sp  // preventing overflows

    STAT_INCREMENT stat_skiped_due_to_disabled

    popfq
    popq %r15
    ret


/// specfuzz_rlbk_if_done: Rollback if we've reached the maximum simulation depth
///
/// CLOB: stack spec
.globl	specfuzz_rlbk_if_done
.type	specfuzz_rlbk_if_done, @function
specfuzz_rlbk_if_done:
    pushfq

    // check if we're in a simulation
    cmpq $0, nesting_level
    je specfuzz_rlbk_if_done.return

    // check if we've passed the speculation window
    cmpq $0, instruction_counter
    jg specfuzz_rlbk_if_done.return

#if ENABLE_STATS == 1
    STAT_INCREMENT stat_max_depth
    cmpq $MAX_NESTING_LEVEL, nesting_level
    jne .L4
        STAT_INCREMENT stat_max_nesting
    .L4:
#endif

    callq specfuzz_rlbk

specfuzz_rlbk_if_done.return:
    popfq
    ret


/// specfuzz_rlbk_forced: Unconditionally rollback the simulation
///
/// CLOB: stack spec
.globl	specfuzz_rlbk_forced
.type	specfuzz_rlbk_forced, @function
specfuzz_rlbk_forced:
    pushfq

    // check if we're in a simulation
    cmpq $0, nesting_level
    je specfuzz_rlbk_forced.return

    callq specfuzz_rlbk

specfuzz_rlbk_forced.return:
    ASSERT checkpoint_sp jle $checkpoint_stack_bottom specfuzz_exit_state_overflow
    movq $checkpoint_stack, checkpoint_sp      // preventing overflows
    popfq
    ret


/// specfuzz_rlbk_*: Wrappers for the rollback function
/// Calculate statistics on what causes simulation aborts
///
/// CLOB: eflags
.globl specfuzz_rlbk_external_call
.type specfuzz_rlbk_external_call, @function
specfuzz_rlbk_external_call:
    STAT_INCREMENT stat_forced_external_call
    jmp specfuzz_rlbk_forced

.globl specfuzz_rlbk_indirect_call
.type specfuzz_rlbk_indirect_call, @function
specfuzz_rlbk_indirect_call:
    STAT_INCREMENT stat_forced_indirect_call
    jmp specfuzz_rlbk_forced

.globl specfuzz_rlbk_serializing
.type specfuzz_rlbk_serializing, @function
specfuzz_rlbk_serializing:
    STAT_INCREMENT stat_forced_serializing_instruction
    jmp specfuzz_rlbk_forced

.globl specfuzz_rlbk_patched
.type specfuzz_rlbk_patched, @function
specfuzz_rlbk_patched:
    STAT_INCREMENT stat_forced_patched
    jmp specfuzz_rlbk_forced


/// specfuzz_rlbk: The rollback routine
///     Never to be called by anything outside the RTL
///
/// Note that we don't bother preserving the previous register values as they will
/// be later overwritten anyway
///
/// CLOB: flags stack spec
.type	specfuzz_rlbk, @function
specfuzz_rlbk:
#if PRINT_ROLLABACK_STATS != 0
    movq simulation_id, %r9
    movq nesting_level, %r8
    movq instruction_counter, %rcx
    movq first_mispredicted_branch, %rdx
    mov $debug_rollback_depth, %esi
    mov stderr, %rdi
    mov $0, %eax
    call _IO_fprintf
#endif

    // Check that we're not overflowing
    movq checkpoint_sp, %rsp
    ASSERT %rsp jle $checkpoint_stack_bottom specfuzz_exit_state_overflow

    // Rewind the Store Log:
    // - First, a special case: a segfault might have been triggered right after
    // the checkpoint, if the page is labeled as read-only
    // Thus, attempting to restore the value will cause another segfault
    // In this case, ignore the broken entry: checkpoint_sp++
    cmp store_log_bp, %rsp
    je .L2
        movq (%rsp), %rbx
        movq 8(%rsp), %rcx
        cmp %rbx, (%rcx)
        jne .L1
        addq $16, %rsp

    // - now, the actual rewind
    .L1: cmp store_log_bp, %rsp
    je .L2
        popq %rbx  // value
        popq %rcx  // address
        movq %rbx, (%rcx)
        jmp .L1
    .L2:

    // Restore FPU and SIMD states
    fxrstor64 (%rsp)
    addq $512, %rsp
    addq $8, %rsp  // alignment

    // Restore the values in the GPRs
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rbp
    popq %rdi
    popq %rsi
    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax

    // Metadata
    popq specfuzz_call_type_stack_sp
    popq disable_speculation
    popq nesting_level
    popq instruction_counter

    // Stack Pointer
    popq current_rsp

    // Overwrite the return address with the checkpoint
    popq return_address

    // EFlags
    popq tmp_eflags

    // Base pointer of the previous Store Log
    popq store_log_bp

    // Update the stack pointer of the Checkpoint Stack
    movq %rsp, checkpoint_sp
    ASSERT %rsp jg $checkpoint_stack specfuzz_exit_state_overflow

#if ENABLE_SEQUENTIAL_SIMULATION == 1
    // When we've reached the level 1, it means we're exiting the simulation
    cmpq $1, nesting_level
    jne .L7
        movq $0, nesting_level
    .L7:
#endif

    // Overwrite the return address with the checkpoint
    movq $specfuzz_rtl_frame, %rsp
    pushq return_address

    // Restore the original value of eflags
    pushq tmp_eflags
    popfq

    ret  // Finish the simulation


//===------------------------------------------------------------------------===//
// Reporting
//===------------------------------------------------------------------------===//

/// specfuzz_report: A callback invoked by ASan when it detects a bounds violation
///
/// rdi: accessed address
/// rsi: location of the offending instruction
/// CLOB: eflags spec
.globl	specfuzz_report
.type	specfuzz_report, @function
specfuzz_report:
    push %rdx
    push %rcx
    push %r8
    push %r9
    push %r10
    push %r11
    push %rax
    push %rbx

    // save the PC for a later use
    movq %rsi, tmp_gpr1

#if REPORT_MEMORY_ERRORS == 1
#if REPORT_WITH_OFFSET == 1
    // get the corresponding address in ASan's shadow memory
    mov %rdi, %rcx
    shr $0x3, %rcx
    addq $0x7fff8000, %rcx

    // TODO: refactor me!
.macro test_offset var
    mov $\var, %rbx
    movzbl (%rcx, %rbx),%edx
    test %dl,%dl
    je specfuzz_report.offset_found
.endm

    test_offset -2
    test_offset -4
    test_offset -8
    test_offset -16
    test_offset -32
    test_offset 2
    test_offset 4
    test_offset 8
    test_offset 16
    test_offset 32

    jmp specfuzz_report.offset_not_found

    specfuzz_report.offset_found:
        movq %rbx, %r8   // offset
        shlq $2, %r8     // the shadow memory is encoded byte-to-bit
        movq $0, %rcx    // accessed address
        jmp specfuzz_report.offset_done

    specfuzz_report.offset_not_found:
        movq $0, %r8
        movq %rdi, %rcx // accessed address
        jmp specfuzz_report.offset_done

    specfuzz_report.offset_done:

#else
    movq $0, %r8  // offset
    movq %rdi, %rcx // accessed address
#endif  // REPORT_WITH_OFFSET

    // report the detected violation
    movq store_log_bp, %r9
    movq CHECKPOINT_STACK_PC_OFFSET(%r9), %r9   // r9 = address of the latest speculated branch
    movq %rsi, %rdx                             // rdx = offending instruction
    mov $asan_detected_overflow_base, %esi
    mov stderr, %rdi
    mov $0, %eax
    call _IO_fprintf

    // iterate over all frames in Checkpoint Stack and print addresses of speculated branches
    movq store_log_bp, %rbx
    .L5:
        movq CHECKPOINT_STACK_BP_OFFSET(%rbx), %rbx  // get previous frame
        test %rbx, %rbx                              // no frames anymore? we're done
        je .L6

        movq CHECKPOINT_STACK_PC_OFFSET(%rbx), %rdx  // rdx = address of the speculated branch
        mov $asan_detected_overflow_next, %esi
        mov stderr, %rdi
        mov $0, %eax
        call _IO_fprintf
        jmp .L5
    .L6:

    // print new line
    movq stderr, %rsi
    movl $10, %edi
    call _IO_putc
#endif  // REPORT_MEMORY_ERRORS

#if COVERAGE_MEMORY_ERRORS == 1
    // report the vulnerability to the fuzzer
    movq tmp_gpr1, %rdi
    call specfuzz_cov_vuln
#endif

    STAT_INCREMENT stat_asan_overflow
    ASSERT nesting_level je $0 specfuzz_exit_asan_overflow

    pop %rbx
    pop %rax
    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rcx
    pop %rdx
    ret

/// specfuzz_report_corrupted_code_pointer:
///
/// Here, we are free to use any registers as we will later proceed with a rollback
/// The stack is also available because we are in a disjoint frame
///
/// rdi: address
/// rsi: location of the offending instruction
/// CLOB: eflags registers spec
.globl	specfuzz_report_corrupted_code_pointer
.type	specfuzz_report_corrupted_code_pointer, @function
specfuzz_report_corrupted_code_pointer:
    ASSERT nesting_level je $0 specfuzz_exit_unknown_corruption
    movq %rsi, tmp_gpr1  // save the PC for a later use
#if REPORT_CONTROL_FLOW_ERRORS == 1
    movq store_log_bp, %r9
    movq CHECKPOINT_STACK_PC_OFFSET(%r9), %r9   // latest speculated branch
    movq $0, %r8                                // offset
    movq %rdi, %rcx                             // accessed address
    movq %rsi, %rdx                             // offending instruction
    mov $detected_corrupted_code_pointer, %esi
    mov stderr, %rdi
    mov $0, %eax
    call _IO_fprintf
#endif
#if COVERAGE_CONTROL_FLOW_ERRORS == 1
    movq tmp_gpr1, %rdi
    call specfuzz_cov_vuln
#endif
    callq specfuzz_rlbk_forced


//===------------------------------------------------------------------------===//
// Misc.
//===------------------------------------------------------------------------===//

/// specfuzz_check_code_pointer: Checks if the pointer that we're about to dereference is within
/// the .text section
///
/// rdi: accessed address
/// CLOB: spec stack
.globl specfuzz_check_code_pointer
.type specfuzz_check_code_pointer, @function
specfuzz_check_code_pointer:
    pushfq
    // TODO: this implementation is very simplistic and will often lead to false positives
    // We need to come up with a better approach to verify a pointer
    // So far, if it makes any trouble, just disable it at compile time
    cmpq $__executable_start, %rdi
    jl specfuzz_check_code_pointer.corrupted
    cmpq $_etext, %rdi
    jl specfuzz_check_code_pointer.ok
    cmpq $_end, %rdi  # bss and data
    jl specfuzz_check_code_pointer.corrupted

specfuzz_check_code_pointer.unknown:
    // We are above BSS, which means we are about to either enter a dynamically linked
    // code (most likely uninstrumented) or to executes some random data
    // We do not report this case, because it could be a desired behavior (dynamic libs),
    // but in both cases we need to rollback
    cmpq $0, nesting_level
    je 1f
    callq specfuzz_rlbk
    1: popfq
    ret

specfuzz_check_code_pointer.ok:
    popfq
    ret

specfuzz_check_code_pointer.corrupted:
    STAT_INCREMENT stat_corrupted_code_pointer
    movq 8(%rsp), %rsi
    addq $8, %rsi
    callq specfuzz_report_corrupted_code_pointer


/// specfuzz_cov_trace_pc_wrapper: Pass the callee address to specfuzz_cov_trace_pc
///
.globl	specfuzz_cov_trace_pc_wrapper
.type	specfuzz_cov_trace_pc_wrapper, @function
specfuzz_cov_trace_pc_wrapper:
#if ENABLE_COVERAGE == 1
    pushq %rdi
    pushq %r11
    pushfq
    movq 24(%rsp), %rdi
    callq specfuzz_cov_trace_pc
    popfq
    popq %r11
    popq %rdi
#endif
    ret


/// specfuzz_exit_*: Exit with an error message
///
specfuzz_exit_unknown_corruption:
    movl $error_not_speculative, %edi
    jmp specfuzz_exit

specfuzz_exit_state_overflow:
    movl $error_checkpoint_stack_overflow, %edi
    jmp specfuzz_exit

specfuzz_exit_asan_overflow:
    movl $asan_detected_real_overflow, %edi
    jmp specfuzz_exit

specfuzz_exit_corrupted_nesting_level:
    movl $error_corrupted_nesting, %edi
    jmp specfuzz_exit

.type	specfuzz_exit, @function
specfuzz_exit:
    movl $0, %eax
    call printf
    movl $42, %edi
    call exit
