CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2 -Iinclude -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fstack-clash-protection -fcf-protection=full -fPIE
LDFLAGS ?= -pie -Wl,-z,relro,-z,now,-z,ibt,-z,shstk -lssl -lcrypto -lcurl -lpthread
ifeq ($(CFI),1)
CFLAGS += -fsanitize=cfi -flto -fvisibility=hidden
LDFLAGS += -fsanitize=cfi -flto
endif

SRCS = main.c \
       attestation/tpm_attestation.c \
       attestation/attestation_client.c \
       attestation/ima_keylime.c \
       device-state/hardware_guard.c \
       device-state/anti_vm.c \
       heartbeat/heartbeat.c \
       heartbeat/offline_buffer.c \
       environment/rf_scanner.c

BUILD_DIR ?= .
COMMON_OBJ = $(BUILD_DIR)/common/examos_appliance.o
OBJS = $(addprefix $(BUILD_DIR)/,$(SRCS:.c=.o)) $(COMMON_OBJ)
OBJECT_ARGS = $(foreach object,$(OBJS),"$(object)")
TARGET = $(BUILD_DIR)/examos-agent

all: $(TARGET)

$(TARGET): $(OBJS)
	@mkdir -p "$(@D)"
	$(CC) $(CFLAGS) -o "$(TARGET)" $(OBJECT_ARGS) $(LDFLAGS)

$(BUILD_DIR)/%.o: %.c
	@mkdir -p "$(@D)"
	$(CC) $(CFLAGS) -c "$<" -o "$@"

# The appliance identity check is shared by the server, the agent and the
# proctoring worker.
$(COMMON_OBJ): ../common/examos_appliance.c ../common/include/examos_appliance.h
	@mkdir -p "$(@D)"
	$(CC) $(CFLAGS) -I../common/include -c "$<" -o "$@"

install: $(TARGET)
	install -d $(DESTDIR)/usr/local/bin
	install -m 755 "$(TARGET)" $(DESTDIR)/usr/local/bin/

clean:
	rm -f $(OBJECT_ARGS) "$(TARGET)"

.PHONY: all install clean
