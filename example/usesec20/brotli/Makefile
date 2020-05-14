SRC := $(patsubst %.c,%,$(wildcard c/dec/*.c)) $(patsubst %.c,%,$(wildcard c/common/*.c)) c/fuzz/decode_fuzzer c/fuzz/run_decode_fuzzer
ifdef PERF
	SRC := $(patsubst %.c,%,$(wildcard c/dec/*.c)) $(patsubst %.c,%,$(wildcard c/enc/*.c)) $(patsubst %.c,%,$(wildcard c/common/*.c)) c/tools/brotli
endif

VPATH := c

include ../common.mk
CFLAGS += -Ic/include -Wno-pointer-sign
LDFLAGS += -lm

clean:
	rm -f c/common/*.o c/dec/*.o c/fuzz/*.o $(ALL_TYPES)