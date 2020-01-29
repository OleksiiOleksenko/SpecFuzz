//===-------- specfuzz_init.c -----------------------------------------------===//
//
// Copyright: This file is distributed under the GPL version 3 License.
// See LICENSE for details.
//
//===------------------------------------------------------------------------===//
/// \file
///
/// - Initialization of the SpecFuzz runtime.
/// - A signal handler that records the signal and does a rollback
//===------------------------------------------------------------------------===//
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <sys/ucontext.h>
#include "specfuzz_rtl.h"

#if ENABLE_STATS == 1
#define STAT_INCREMENT(X) X++
#else
#define STAT_INCREMENT(X)
#endif

// a disjoint stack frame for a signal handler
stack_t signal_stack_descr;
char signal_stack[SIGSTKSZ];

// a global variable for detecting errors in RTL
char inside_handler = 0;

// output buffer
#define OUTPUT_SIZE 1000000
char output[OUTPUT_SIZE];

/// Signal handler to catch exceptions on simulated paths
///
void specfuzz_handler(int signo, siginfo_t *siginfo, void *ucontext) {
    ucontext_t *context = ((ucontext_t *) ucontext);
    greg_t *uc_gregs = context->uc_mcontext.gregs;

#if ENABLE_SANITY_CHECKS == 1
    if (inside_handler != 0) {
        fprintf(stderr, "\n[SF] Error: Fault inside the signal handler\n");
        abort();
    }
    inside_handler = 1;

    if (nesting_level <= 0x0) {
        fprintf(stderr, "[SF] Error: Signal handler called outside speculation\n");
        abort();
    }

    if (checkpoint_sp > &checkpoint_stack || checkpoint_sp < &checkpoint_stack_bottom) {
        fprintf(stderr, "[SF] Error: checkpoint_sp is corrupted\n");
        abort();
    }

    if ((uint64_t *) uc_gregs[REG_RSP] <= &specfuzz_rtl_frame
        && (uint64_t *) uc_gregs[REG_RSP] >= &specfuzz_rtl_frame_bottom) {
        fprintf(stderr, "[SF] Error: a signal caught within the SpecFuzz runtime\n");
        abort();
    }
#endif

    if (siginfo->si_signo == SIGFPE) {
        STAT_INCREMENT(stat_signal_misc);
    } else {
        long long int instruction = context->uc_mcontext.gregs[REG_RIP];
#if ENABLE_PRINT == 1
        // Print information about the signal
        // Note: the calls to fprintf are not multithreading-safe

        // the speculated branch's PC is stored in the second entry of
        // the current checkpoint stack frame, or the 16's entry if we go backwards
        // TODO: these indexes are ugly. Use a structure instead
        uint64_t last_branch_address = store_log_bp[20 + 64 + 1];
        fprintf(stderr,
                "[SF], %d, 0x%llx, 0x%lx, 0, 0x%lx",
                siginfo->si_signo,
                instruction,
                (unsigned long int) siginfo->si_addr,
                last_branch_address);
        uint64_t *next_frame = (uint64_t *) store_log_bp[22 + 64 + 1];
        while (next_frame) {
            fprintf(stderr, ", 0x%lx", next_frame[20 + 64 + 1]);
            next_frame = (uint64_t *) next_frame[22 + 64 + 1];
        }
        fprintf(stderr, "\n");
#endif

#if ENABLE_COVERAGE == 1
        specfuzz_cov_vuln(instruction);
#endif
        STAT_INCREMENT(stat_signal_overflow);
    }

    // Redirect the flow into the recovery function
    uc_gregs[REG_RSP] = (greg_t) &specfuzz_rtl_frame;
    uc_gregs[REG_RIP] = (greg_t) &specfuzz_rlbk_forced;
    inside_handler = 0;
}

/// Catch all hardware signals with our handler
///
void setup_handler() {
    // Establish an alternate stack for the handler
    signal_stack_descr.ss_sp = &signal_stack;
    signal_stack_descr.ss_size = SIGSTKSZ;
    signal_stack_descr.ss_flags = 0;

    if (sigaltstack(&signal_stack_descr, NULL) == -1) {
        perror("sigaltstack");
        _exit(1);
    }

    // Configure the signal handler
    struct sigaction action;
    action.sa_sigaction = specfuzz_handler;
    sigemptyset(&action.sa_mask);  // do not mask any signals while handling

    // pass signal info, use alternate stack, and catch it's own signals
    action.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER;

    // Register the handler
    if (sigaction(SIGSEGV, &action, NULL) == -1 ||
        sigaction(SIGBUS, &action, NULL) == -1 ||
        sigaction(SIGILL, &action, NULL) == -1 ||
        sigaction(SIGTRAP, &action, NULL) == -1 ||
        sigaction(SIGFPE, &action, NULL) == -1) {
        perror("sigaction");
        _exit(1);
    }
}

/// Prints runtime statistics
///
#define print_stat(MSG, VAR, TOTAL) fprintf(stderr, MSG, VAR, (VAR * 100) / TOTAL)
void specfuzz_dump_stats() {
    uint64_t total = stat_max_depth + stat_corrupted_code_pointer + stat_forced_external_call
        + stat_forced_serializing_instruction + stat_forced_indirect_call + stat_asan_overflow
        + stat_signal_overflow + stat_signal_misc;
    fprintf(stderr, "[SF] Statistics:\n");
    print_stat("  Max speculation depth reached: %lu (%lu%%)\n", stat_max_depth, total);
    print_stat("     of them, with max nesting %lu (%lu%%)\n", stat_max_nesting, total);
    print_stat("  External function call: %lu (%lu%%)\n", stat_forced_external_call, total);
    print_stat("  Indirect function call: %lu (%lu%%)\n", stat_forced_indirect_call, total);
    print_stat("  Serializing: %lu (%lu%%)\n", stat_forced_serializing_instruction, total);
    print_stat("  Bounds violation (ASan): %lu (%lu%%)\n", stat_asan_overflow, total);
    print_stat("  Bounds violation (signal): %lu (%lu%%)\n", stat_signal_overflow, total);
    print_stat("  Corrupted code pointer: %lu (%lu%%)\n", stat_corrupted_code_pointer, total);
    print_stat("  Other signals: %lu (%lu%%)\n", stat_signal_misc, total);
    fprintf(stderr, "  Simulation disables: %lu\n", stat_simulation_disables);
    fprintf(stderr, "  Skipped CMP due to disabled simulation: %lu\n", stat_skiped_due_to_disabled);
}

/// The initialization function. Called before main
///
__attribute__((preserve_most))
void specfuzz_init() {
    // _IOFBF behaves funky. IDK why. Gave up on it for the time being
    setvbuf(stderr, output, _IOLBF, OUTPUT_SIZE);
    fprintf(stderr, "[SF] Starting\n");
    setup_handler();
#if ENABLE_STATS == 1
    atexit(specfuzz_dump_stats);
#endif
#if ENABLE_COVERAGE == 1
    specfuzz_cov_init();
#endif

}
