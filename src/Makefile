BPF_CLANG=clang
BPF_CFLAGS=-g -O2 -target bpf
USER_CFLAGS=-g -O2 -Wall
LIBS=-lbpf -lelf -lz

all: loader

test.bpf.o: test.bpf.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

test.skel.h: test.bpf.o
	./bin/bpftool gen skeleton $< > $@

loader: main.c test.skel.h
	clang $(USER_CFLAGS) -I. -o loader main.c $(LIBS)

clean:
	rm -f *.o *.skel.h loader
