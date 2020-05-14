SRC := fuzz http_parser

ifdef PERF
	SRC := bench http_parser
endif

VPATH := .

CFLAGS := -I. -DHTTP_PARSER_STRICT=1

include ../common.mk

clean:
	rm -f *.o $(ALL_TYPES)