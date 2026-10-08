CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong
TARGET = examos-kiosk-launcher

all: $(TARGET)

$(TARGET): launcher.c
	$(CC) $(CFLAGS) -o $(TARGET) launcher.c

install: $(TARGET)
	install -d $(DESTDIR)/usr/local/bin
	install -m 755 $(TARGET) $(DESTDIR)/usr/local/bin/

clean:
	rm -f $(TARGET)

.PHONY: all install clean
