//===-------- specfuzz_rtl.h ------------------------------------------------===//
//
// Copyright: This file is distributed under the GPL version 3 License.
// See LICENSE for details.
//
//===------------------------------------------------------------------------===//
/// \file
///
//===------------------------------------------------------------------------===//
#ifndef SPECFUZZ_RTL_H
#define SPECFUZZ_RTL_H
#include <stdint.h>

// global variables declared in specfuzz_rtl.S
extern uint64_t nesting_level;
extern int64_t disable_speculation;
extern uint64_t *store_log_bp;
extern uint64_t branch_execution_count;

extern uint64_t specfuzz_rtl_frame;
extern uint64_t specfuzz_rtl_frame_bottom;

extern uint64_t asan_rtl_frame;
extern uint64_t asan_rtl_frame_bottom;

extern uint64_t *checkpoint_sp;
extern uint64_t checkpoint_stack;
extern uint64_t checkpoint_stack_bottom;

extern uint64_t stat_max_depth;
extern uint64_t stat_forced_external_call;
extern uint64_t stat_forced_indirect_call;
extern uint64_t stat_forced_serializing_instruction;
extern uint64_t stat_max_nesting;
extern uint64_t stat_asan_overflow;
extern uint64_t stat_signal_overflow;
extern uint64_t stat_corrupted_code_pointer;
extern uint64_t stat_signal_misc;
extern uint64_t stat_simulation_disables;
extern uint64_t stat_skiped_due_to_disabled;

extern void specfuzz_rlbk_forced(void);

// Coverage
void specfuzz_cov_init();
__attribute__((weak)) __attribute__((preserve_most))
void specfuzz_cov_trace_pc(uintptr_t pc);
__attribute__((weak))
void specfuzz_cov_vuln(uintptr_t pc);
__attribute__((weak)) __attribute__((preserve_most))
struct map_entry_t *get_hash_map_entry(uintptr_t pc);


#endif //SPECFUZZ_RTL_H
