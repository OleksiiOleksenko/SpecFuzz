CC ?= clang
CFLAGS ?= -O3 -ggdb
RTLIB ?= -lspecfuzz

.SUFFIXES:  # disable built-in rules
.PHONY: all

TESTS := dummy rtl_chkp rtl_chkp_rlbk acceptance-basic acceptance-mmul


all:
	echo "no default"

%: %.S libtest.a
	$(CC) $(CFLAGS) $< -o $@ $(RTLIB) -ltest -L.

%: %.c libtest.a
	$(CC) $(CFLAGS) $< -o $@ $(RTLIB) -ltest -L.

libtest.a:
	$(CC) $(CFLAGS) common/asm_test_runner.c -c -o asm_test_runner.o
	$(CC) $(CFLAGS) common/process_state.S -c -o process_state.o
	ar rc $@ asm_test_runner.o process_state.o
	rm asm_test_runner.o process_state.o

clean:
	rm -f *.o $(TESTS)
