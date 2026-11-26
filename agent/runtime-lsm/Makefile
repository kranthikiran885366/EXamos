CC ?= gcc
CLANG ?= clang
BUILD_DIR ?= .
CPPFLAGS ?=
CFLAGS ?= -O2 -Wall -Wextra -Werror -D_FORTIFY_SOURCE=2 -fstack-protector-strong
BPF_CFLAGS ?= -I/usr/include/$(shell $(CC) -dumpmachine)
LDLIBS ?= -lbpf
all: $(BUILD_DIR)/examos-bpf-lsm $(BUILD_DIR)/runtime.bpf.o
$(BUILD_DIR)/examos-bpf-lsm: main.c
	mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) "$<" $(LDFLAGS) $(LDLIBS) -o "$@"
$(BUILD_DIR)/runtime.bpf.o: runtime.bpf.c
	mkdir -p "$(BUILD_DIR)"
	$(CLANG) -target bpf -g -O2 -Wall -Wextra -Werror $(BPF_CFLAGS) -c "$<" -o "$@"
clean:
	rm -f "$(BUILD_DIR)/examos-bpf-lsm" "$(BUILD_DIR)/runtime.bpf.o"
.PHONY: all clean
