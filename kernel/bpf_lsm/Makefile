CLANG ?= clang
BPFTOOL ?= bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -Wall -Werror

all: examos_lsm.bpf.o

examos_lsm.bpf.o: examos_lsm.bpf.c
	$(CLANG) $(CFLAGS) -c $< -o $@

verify: examos_lsm.bpf.o
	$(BPFTOOL) prog loadall examos_lsm.bpf.o /sys/fs/bpf/examos type lsm

clean:
	rm -f examos_lsm.bpf.o
