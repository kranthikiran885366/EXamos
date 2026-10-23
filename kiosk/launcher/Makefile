CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong
BUILD_DIR ?= .
TARGET = $(BUILD_DIR)/examos-kiosk-launcher

all: $(TARGET)

$(TARGET): launcher.c
	@mkdir -p "$(@D)"
	$(CC) $(CFLAGS) -o "$(TARGET)" launcher.c ../../server/admin/config_manager.c -lcrypto

install: $(TARGET)
	install -d $(DESTDIR)/usr/local/bin
	install -m 755 "$(TARGET)" $(DESTDIR)/usr/local/bin/

clean:
	rm -f $(TARGET)

.PHONY: all install clean
