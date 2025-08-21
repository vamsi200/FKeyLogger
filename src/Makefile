BPF_CLANG := clang
BPF_CFLAGS := -g -O2 -target bpf

USER_CLANG := clang
USER_CFLAGS := -g -O2 -Wall
LIBS := -lbpf -lelf -lz

.PHONY: all clean

all: vfsread_bin memfd_bin

vfsread.bpf.o: vfsread.bpf.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

memfd.bpf.o: memfd.bpf.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

vfsread.skel.h: vfsread.bpf.o
	./bin/bpftool gen skeleton $< > $@.tmp && mv $@.tmp $@

memfd.skel.h: memfd.bpf.o
	./bin/bpftool gen skeleton $< > $@.tmp && mv $@.tmp $@

vfsread_bin: main.c vfsread.skel.h
	$(USER_CLANG) $(USER_CFLAGS) -I. -o $@ main.c $(LIBS)

memfd_bin: memfd_main.c memfd.skel.h
	$(USER_CLANG) $(USER_CFLAGS) -I. -o $@ memfd_main.c $(LIBS)

clean:
	$(RM) -f *.o *.skel.h vfsread_bin memfd_bin
