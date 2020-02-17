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
	$(CC) $(CFLAGS) $< -o $@ $(RTLIB)

libtest.a: common/process_state.S
	# here, we must use a normal, non-SpecFuzz compiler to avoid the instrumentation
	gcc $(CFLAGS) common/process_state.S -c -o process_state.o
	ar rc $@ process_state.o
	rm process_state.o

clean:
	rm -f *.o $(TESTS)
