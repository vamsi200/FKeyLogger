BPF_CLANG := clang
BPF_CFLAGS := -g -O2 -target bpf

USER_CLANG := clang
USER_CFLAGS := -g -O2 -Wall
LIBS := -lbpf -lelf -lz

.PHONY: all clean

all: input_monitor_bin memfd_bin

input_monitor.bpf.o: input_monitor.bpf.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

memfd.bpf.o: memfd.bpf.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

input_monitor.skel.h: input_monitor.bpf.o
	./bin/bpftool gen skeleton $< > $@.tmp && mv $@.tmp $@

memfd.skel.h: memfd.bpf.o
	./bin/bpftool gen skeleton $< > $@.tmp && mv $@.tmp $@

input_monitor_bin: main.c input_monitor.skel.h
	$(USER_CLANG) $(USER_CFLAGS) -I. -o $@ main.c $(LIBS)

memfd_bin: memfd_main.c memfd.skel.h
	$(USER_CLANG) $(USER_CFLAGS) -I. -o $@ memfd_main.c $(LIBS)

clean:
	$(RM) -f *.o *.skel.h input_monitor_bin memfd_bin
