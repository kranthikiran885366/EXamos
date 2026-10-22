CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2 -Iinclude -D_FORTIFY_SOURCE=2 -fstack-protector-strong
LDFLAGS ?= -lssl -lcrypto -lcurl -lpthread

SRCS = main.c \
       attestation/tpm_attestation.c \
       attestation/attestation_client.c \
       device-state/hardware_guard.c \
       heartbeat/heartbeat.c \
       environment/rf_scanner.c

OBJS = $(SRCS:.c=.o)
TARGET = examos-agent

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

install: $(TARGET)
	install -d $(DESTDIR)/usr/local/bin
	install -m 755 $(TARGET) $(DESTDIR)/usr/local/bin/

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all install clean
