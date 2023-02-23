CFLAGS += -g3 \
          -Wall

LIBS = bpf

all: fib_lookup.bpf.o fib_lookup.skel.h test

fib_lookup.bpf.o: fib_lookup.bpf.c
	clang -target bpf -Wall -O2 -g -c $<

fib_lookup.skel.h: fib_lookup.bpf.o
	bpftool gen skeleton $< > $@

test: test.c
	gcc $(CFLAGS) -l$(LIBS) -o $@ $<

.PHONY:
clean:
	rm -rf fib_lookup.bpf.o
	rm -rf fib_lookup.skel.h
	rm -rf test