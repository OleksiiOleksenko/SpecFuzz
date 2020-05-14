SRC := fuzz jsmn
ifdef PERF
	SRC := bench jsmn
endif

VPATH := .

CFLAGS := -I.

include ../common.mk

clean:
	rm -f *.o $(ALL_TYPES)