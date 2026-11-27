CLANG ?= clang
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
BPF_CFLAGS ?= -O2 -g -Wall -target bpf -D__TARGET_ARCH_$(ARCH) -idirafter /usr/include/$(shell uname -m)-linux-gnu

all: examos_xdp_filter.bpf.o

examos_xdp_filter.bpf.o: examos_xdp_filter.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -f examos_xdp_filter.bpf.o

.PHONY: all clean
