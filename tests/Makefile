LLVM_CONFIG ?= llvm-7.0.1-config
CLANG_PATH := $(shell $(LLVM_CONFIG) --bindir)
RTLIB := -lspecfuzz

.SUFFIXES:  # disable built-in rules
.PHONY: all

all:
	echo "no default"

%: %.S libtest.a
	clang -O3 -ggdb $< -o $@ $(RTLIB) -ltest -L.

libtest.a:
	clang -O3 -ggdb common/asm_test_runner.c -c -o asm_test_runner.o
	clang -O3 -ggdb common/process_state.S -c -o process_state.o
	ar rc $@ asm_test_runner.o process_state.o
	rm asm_test_runner.o process_state.o

clean:
	rm -f *.o
