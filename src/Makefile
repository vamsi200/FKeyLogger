BPF_CLANG=clang
BPF_CFLAGS=-g -O2 -target bpf
USER_CFLAGS=-g -O2 -Wall
LIBS=-lbpf -lelf -lz

all: vfsread_bin

vfsread.bpf.o: vfsread.bpf.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

vfsread.skel.h: vfsread.bpf.o
	./bin/bpftool gen skeleton $< > $@

vfsread_bin: main.c vfsread.skel.h
	clang $(USER_CFLAGS) -I. -o vfsread_bin main.c $(LIBS)
clean:
	rm -f *.o *.skel.h loader
