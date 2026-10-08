CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2 -Iinclude -D_FORTIFY_SOURCE=2 -fstack-protector-strong
LDFLAGS ?= -lssl -lcrypto -lpthread

SRCS = main.c \
       events/ledger.c \
       risk/risk_engine.c \
       exam/exam_service.c \
       admin/config_manager.c \
       login/candidate_login.c \
       admin/admin_dashboard.c

OBJS = $(SRCS:.c=.o)
TARGET = examos-server

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
