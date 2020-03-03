# Configuration
ENABLE_PRIORITEZED_SIMULATION ?= 1
ENABLE_PRINT ?= 1
ENABLE_PRINT_OFFSET ?= 0
ENABLE_COVERAGE ?= 1
ENABLE_SANITY_CHECKS ?= 1
ENABLE_STATS ?= 0
ENABLE_SEQUENTIAL_SIMULATION ?= 0
DUMP_COVERAGE_AT_EXIT ?= 0
PRINT_ROLLABACK_STATS ?= 0
MAX_NESTING_LEVEL ?= 1

RUNTIME_CONFIGURATION := -DMAX_NESTING_LEVEL=$(MAX_NESTING_LEVEL)\
 -DENABLE_PRIORITEZED_SIMULATION=$(ENABLE_PRIORITEZED_SIMULATION)\
 -DENABLE_PRINT=$(ENABLE_PRINT) -DENABLE_PRINT_OFFSET=$(ENABLE_PRINT_OFFSET)\
 -DENABLE_COVERAGE=$(ENABLE_COVERAGE) -DENABLE_SANITY_CHECKS=$(ENABLE_SANITY_CHECKS)\
 -DENABLE_STATS=$(ENABLE_STATS) -DENABLE_SEQUENTIAL_SIMULATION=$(ENABLE_SEQUENTIAL_SIMULATION)\
 -DDUMP_COVERAGE_AT_EXIT=$(DUMP_COVERAGE_AT_EXIT) -DPRINT_ROLLABACK_STATS=$(PRINT_ROLLABACK_STATS)

# Paths
LLVM_CONFIG ?= llvm-7.0.1-config
LLVM_SRC := $(shell $(LLVM_CONFIG) --src-root)
COMPILER_RT_SRC ?= $(LLVM_SRC)/tools/compiler-rt-7.0.1.src
LLVM_BUILD := $(shell $(LLVM_CONFIG) --bindir)/..
CLANG := $(shell $(LLVM_CONFIG) --bindir)/clang
INSTALL_DIR := $(LLVM_SRC)/lib/Target/X86/
export INSTALL_DIR

# Files by categories
RUNTIME := src/specfuzz_rtl.S src/specfuzz_init.c src/specfuzz_cov.c
LLVM_PATCH := $(wildcard install/patches/llvm/*)
HONGG_PATCH := $(wildcard install/patches/honggfuzz/*)

# =============
# Targets
# =============
all: pass runtime patch_llvm rebuild_llvm
install: install_specfuzz install_tools

pass: src/SpecFuzzPass.cpp
	cp $< $(INSTALL_DIR)/SpecFuzzPass.cpp

runtime: $(RUNTIME)
	${CLANG} -O3 src/specfuzz_init.c -o specfuzz_init.o -c -ggdb3 $(RUNTIME_CONFIGURATION)
	${CLANG} -O3 src/specfuzz_rtl.S -o specfuzz_rtl.o -c -ggdb3 $(RUNTIME_CONFIGURATION)
	${CLANG} -O3 src/specfuzz_cov.c -o specfuzz_cov.o -c -ggdb3 $(RUNTIME_CONFIGURATION)
	ar rc $(LLVM_BUILD)/lib/libspecfuzz.a specfuzz_init.o specfuzz_rtl.o specfuzz_cov.o
	rm specfuzz_rtl.o specfuzz_init.o

patch_llvm: $(LLVM_PATCH)
	# Connect SpecFuzz
	cp install/patches/llvm/CMakeLists.txt install/patches/llvm/X86.h install/patches/llvm/X86TargetMachine.cpp $(LLVM_SRC)/lib/Target/X86/

	# ASan patch
	cp install/patches/llvm/asan_poisoning.cc install/patches/llvm/asan_rtl.cc $(COMPILER_RT_SRC)/lib/asan/
	cp install/patches/llvm/sanitizer_coverage_libcdep_new.cc $(COMPILER_RT_SRC)/lib/sanitizer_common/

	# SLH patch
	cp install/patches/llvm/X86SpeculativeLoadHardening.cpp $(LLVM_SRC)/lib/Target/X86/

rebuild_llvm:
	make -j -C $(LLVM_BUILD)

install_specfuzz:
	cp -u install/wrapper.sh /usr/bin/clang-sf
	cp -u install/wrapper.sh /usr/bin/clang-sf++
	sed -i -e 's:/clang$$:/clang++:g' /usr/bin/clang-sf++

install_tools: analyzer hongg

analyzer: postprocessing/analyzer.py
	cp $< /usr/bin/analyzer

hongg: check_hongg_path patch_hongg rebuild_hongg

check_hongg_path:
ifndef HONGG_SRC
	$(error HONGG_SRC is not set)
else
	@echo ""
endif

patch_hongg: $(HONGG_PATCH)
	cp install/patches/honggfuzz/instrument.c $(HONGG_SRC)/libhfuzz/instrument.c
	cp install/patches/honggfuzz/fuzz.c $(HONGG_SRC)/fuzz.c
	cp install/patches/honggfuzz/honggfuzz.h $(HONGG_SRC)/honggfuzz.h
	cp install/patches/honggfuzz/trace.c $(HONGG_SRC)/linux/trace.c
	sed -i -e 's:_HF_PERSISTENT_SIG:"":g' $(HONGG_SRC)/libhfuzz/fetch.c

rebuild_hongg:
	CC=${CLANG} CFLAGS=-ggdb make -C $(HONGG_SRC) -j4
	make -C $(HONGG_SRC) install

test:
	cd tests && ./run.bats
