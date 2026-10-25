CC ?= gcc
PG_CONFIG ?= pg_config
PG_INCLUDEDIR := $(shell $(PG_CONFIG) --includedir 2>/dev/null)
PG_LIBDIR := $(shell $(PG_CONFIG) --libdir 2>/dev/null)
CFLAGS ?= -Wall -Wextra -O2 -Iinclude -Idb -Isecurity -Iaudit -Icontrollers -D_FORTIFY_SOURCE=2 -fstack-protector-strong
CPPFLAGS += -I$(PG_INCLUDEDIR) -DUSE_OPENSSL_TLS
LDFLAGS ?= -lssl -lcrypto -lpthread -L$(PG_LIBDIR) -lpq -lm

SRCS = main.c \
       events/ledger.c \
       events/event_chain.c \
       risk/risk_engine.c \
       exam/exam_service.c \
       exam/exam_engine.c \
       behaviour/behaviour_engine.c \
       behaviour/variant_engine.c \
       behaviour/viva_engine.c \
       environment/e1_consent.c \
       environment/environment_engine.c \
       network/firewall_service.c \
       admin/config_manager.c \
       admin/admin_auth_store.c \
       admin/enterprise_platform.c \
       admin/policy_catalog.c \
       security/secure_token.c \
       security/totp.c \
       login/candidate_login.c \
       login/session_store.c \
       admin/admin_dashboard.c \
       attestation/attestation_service.c \
       attestation/attestation_config.c \
       attestation/tpm_quote.c \
       gateway/key_release.c \
       proctoring/second_camera.c \
       db/db.c \
       security/security.c \
       audit/audit.c \
       controllers/controller.c \
       controllers/auth_controller.c \
       controllers/institution_controller.c \
       controllers/exam_controller.c \
       controllers/candidate_controller.c \
       controllers/device_controller.c \
       controllers/tpm_controller.c \
       controllers/session_controller.c \
       controllers/release_controller.c \
       controllers/policy_controller.c \
       controllers/modules_controller.c

BUILD_DIR ?= .
COMMON_OBJ = $(BUILD_DIR)/common/examos_appliance.o
OBJS = $(addprefix $(BUILD_DIR)/,$(SRCS:.c=.o)) $(COMMON_OBJ)
OBJECT_ARGS = $(foreach object,$(OBJS),"$(object)")
TARGET = $(BUILD_DIR)/examos-server
MIGRATOR = $(BUILD_DIR)/examos-db-migrate
ADMIN_PROVISIONER = $(BUILD_DIR)/examos-admin-provision
ADMIN_PROVISIONER_SRCS = admin/admin_provision.c admin/admin_auth_store.c \
                         admin/config_manager.c security/secure_token.c \
                         security/totp.c

all: $(TARGET) $(MIGRATOR) $(ADMIN_PROVISIONER)

$(TARGET): $(OBJS)
	@mkdir -p "$(@D)"
	$(CC) $(CFLAGS) -o "$(TARGET)" $(OBJECT_ARGS) $(LDFLAGS)

$(MIGRATOR): admin/db_migrate.c
	@mkdir -p "$(@D)"
	$(CC) $(CPPFLAGS) $(CFLAGS) -o "$(MIGRATOR)" admin/db_migrate.c $(LDFLAGS)

$(ADMIN_PROVISIONER): $(ADMIN_PROVISIONER_SRCS)
	@mkdir -p "$(@D)"
	$(CC) $(CPPFLAGS) $(CFLAGS) -o "$(ADMIN_PROVISIONER)" $(ADMIN_PROVISIONER_SRCS) $(LDFLAGS)

$(BUILD_DIR)/%.o: %.c
	@mkdir -p "$(@D)"
	$(CC) $(CPPFLAGS) $(CFLAGS) -c "$<" -o "$@"

# The appliance identity check is shared by the server, the agent and the
# proctoring worker.
$(COMMON_OBJ): ../common/examos_appliance.c ../common/include/examos_appliance.h
	@mkdir -p "$(@D)"
	$(CC) $(CPPFLAGS) $(CFLAGS) -I../common/include -c "$<" -o "$@"

install: $(TARGET) $(MIGRATOR) $(ADMIN_PROVISIONER)
	install -d $(DESTDIR)/usr/local/bin
	install -m 755 "$(TARGET)" $(DESTDIR)/usr/local/bin/
	install -m 755 "$(MIGRATOR)" $(DESTDIR)/usr/local/bin/
	install -m 755 "$(ADMIN_PROVISIONER)" $(DESTDIR)/usr/local/bin/
	install -d $(DESTDIR)/usr/share/examos/migrations
	install -m 644 migrations/*.sql $(DESTDIR)/usr/share/examos/migrations/

test-attestation-db:
	@set -eu; test_binary=$$(mktemp "$${TMPDIR:-/tmp}/examos-attestation-db.XXXXXX"); \
	trap 'rm -f -- "$$test_binary"' EXIT; \
	$(CC) $(CPPFLAGS) $(CFLAGS) ../tests/server/attestation_db_integration_test.c \
		$(LDFLAGS) -o "$$test_binary"; \
	"$$test_binary"

test-ledger:
	@set -eu; test_binary=$$(mktemp "$${TMPDIR:-/tmp}/examos-ledger-test.XXXXXX"); \
	trap 'rm -f -- "$$test_binary"' EXIT; \
	$(CC) $(CPPFLAGS) $(CFLAGS) ../tests/server/ledger-recovery-test.c \
		$(BUILD_DIR)/events/ledger.o $(LDFLAGS) -o "$$test_binary"; \
	"$$test_binary"

test-admin-rate-limit:
	@set -eu; test_binary=$$(mktemp "$${TMPDIR:-/tmp}/examos-rate-limit-test.XXXXXX"); \
	trap 'rm -f -- "$$test_binary"' EXIT; \
	$(CC) $(CPPFLAGS) $(CFLAGS) ../tests/server/admin-rate-limit-test.c \
		$(BUILD_DIR)/admin/admin_auth_store.o $(BUILD_DIR)/admin/config_manager.o \
		$(BUILD_DIR)/admin/enterprise_platform.o $(BUILD_DIR)/security/secure_token.o \
		$(BUILD_DIR)/security/totp.o $(BUILD_DIR)/events/ledger.o $(LDFLAGS) -o "$$test_binary"; \
	"$$test_binary"

clean:
	rm -f $(OBJECT_ARGS) "$(TARGET)" "$(MIGRATOR)" "$(ADMIN_PROVISIONER)"

.PHONY: all install clean test-attestation-db test-ledger test-admin-rate-limit
