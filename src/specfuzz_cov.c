//===-------- specfuzz_cov.c ------------------------------------------------===//
//
// Copyright: This file is distributed under the GPL version 3 License.
// See LICENSE for details.
//
//===------------------------------------------------------------------------===//
/// \file
///
/// Dummy default implementations of SpecFuzz coverage functions.
/// Used mainly for testing
///
/// The corresponding strong symbols must be defined by the fuzzer
//===------------------------------------------------------------------------===//
#include "specfuzz_rtl.h"

void specfuzz_cov_init() {}

__attribute__((weak)) __attribute__((preserve_most))
void specfuzz_cov_trace_pc(uintptr_t pc) {
    branch_execution_count = 1;
}

__attribute__((weak))
void specfuzz_cov_vuln(uintptr_t pc) {}