RUSTC ?= rustc
BUILD_DIR ?= .
TARGET = $(BUILD_DIR)/examos-runtime-guard
all: $(TARGET)
$(TARGET): main.rs
	mkdir -p "$(BUILD_DIR)"
	$(RUSTC) --edition=2021 -D warnings -C opt-level=2 -C panic=abort -C strip=symbols main.rs -o "$@"
test:
	@set -eu; binary=$$(mktemp); trap 'rm -f "$$binary"' EXIT; \
	$(RUSTC) --edition=2021 -D warnings --test main.rs -o "$$binary"; "$$binary"
install: $(TARGET)
	install -D -m 0755 "$(TARGET)" "$(DESTDIR)/usr/local/bin/examos-runtime-guard"
clean:
	rm -f "$(TARGET)"
.PHONY: all test install clean
