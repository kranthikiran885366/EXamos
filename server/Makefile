CC ?= gcc
PG_CONFIG ?= pg_config
PG_INCLUDEDIR := $(shell $(PG_CONFIG) --includedir 2>/dev/null)
PG_LIBDIR := $(shell $(PG_CONFIG) --libdir 2>/dev/null)
CFLAGS ?= -Wall -Wextra -O2 -Iinclude -D_FORTIFY_SOURCE=2 -fstack-protector-strong
CPPFLAGS += -I$(PG_INCLUDEDIR)
LDFLAGS ?= -lssl -lcrypto -lpthread -L$(PG_LIBDIR) -lpq

SRCS = main.c \
       events/ledger.c \
       events/event_chain.c \
       risk/risk_engine.c \
       exam/exam_service.c \
       admin/config_manager.c \
       admin/admin_auth_store.c \
       admin/enterprise_platform.c \
       security/secure_token.c \
       security/totp.c \
       login/candidate_login.c \
       admin/admin_dashboard.c \
       attestation/attestation_service.c \
       attestation/attestation_config.c \
       attestation/tpm_quote.c \
       gateway/key_release.c \
       proctoring/second_camera.c

OBJS = $(SRCS:.c=.o)
TARGET = examos-server
MIGRATOR = examos-db-migrate

all: $(TARGET) $(MIGRATOR)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

$(MIGRATOR): admin/db_migrate.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $(MIGRATOR) admin/db_migrate.c $(LDFLAGS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

install: $(TARGET) $(MIGRATOR)
	install -d $(DESTDIR)/usr/local/bin
	install -m 755 $(TARGET) $(DESTDIR)/usr/local/bin/
	install -m 755 $(MIGRATOR) $(DESTDIR)/usr/local/bin/
	install -d $(DESTDIR)/usr/share/examos/migrations
	install -m 644 migrations/*.sql $(DESTDIR)/usr/share/examos/migrations/

test-attestation-db:
	@set -eu; test_binary=$$(mktemp "$${TMPDIR:-/tmp}/examos-attestation-db.XXXXXX"); \
	trap 'rm -f -- "$$test_binary"' EXIT; \
	$(CC) $(CPPFLAGS) $(CFLAGS) ../tests/server/attestation_db_integration_test.c \
		$(LDFLAGS) -o "$$test_binary"; \
	"$$test_binary"

clean:
	rm -f $(OBJS) $(TARGET) $(MIGRATOR)

.PHONY: all install clean test-attestation-db
