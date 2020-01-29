NAME := demo
SRC := main sizes

CC = clang
CXX = clang++
CFLAGS := -fsanitize=address -O1 -ggdb

CCSF = clang-sf
CXXSF = clang-sf++
SF_CFLAGS := -fsanitize=address -O1 -ggdb

all: sf

native: $(addsuffix .o, $(SRC))
	$(CC) $(CFLAGS) $? -o $(NAME)-native

%.o: %.c
	$(CC) $(CFLAGS) $< -c -o $@

sf: $(addsuffix .sf.o, $(SRC))
	$(CCSF) $(SF_CFLAGS) $? -o $(NAME)-sf

%.sf.o: %.c
	$(CCSF) $(SF_CFLAGS) $< -c -o $@

clean:
	rm -f *.o $(NAME)-native $(NAME)-sf