# ExamOS Master Native C/C++ Build Makefile

SUBDIRS = kiosk/launcher agent proctoring server
# BUILD_ROOT is the canonical isolated-output directory.  BUILD_DIR remains a
# supported compatibility alias because the CI workflows historically passed
# that name at the repository root.  Honour it here rather than silently
# writing binaries into source directories.
ifneq ($(strip $(BUILD_DIR)),)
BUILD_ROOT ?= $(BUILD_DIR)
endif
BUILD_ROOT ?=

all:
	@for dir in $(SUBDIRS); do \
		echo "=== Building $$dir ==="; \
		if [ -n "$(BUILD_ROOT)" ]; then \
			$(MAKE) -C $$dir BUILD_DIR="$(BUILD_ROOT)/$$dir" all || exit 1; \
		else \
			$(MAKE) -C $$dir all || exit 1; \
		fi; \
	done
	@echo "=== All ExamOS Native Subsystems Built Successfully ==="

# CI and release tooling use this explicit name.  Keep it an alias for the
# complete native build; it must never be a partial or development-only build.
native: all

install:
	@for dir in $(SUBDIRS); do \
		echo "=== Installing $$dir ==="; \
		if [ -n "$(BUILD_ROOT)" ]; then \
			$(MAKE) -C $$dir BUILD_DIR="$(BUILD_ROOT)/$$dir" install || exit 1; \
		else \
			$(MAKE) -C $$dir install || exit 1; \
		fi; \
	done

clean:
	@for dir in $(SUBDIRS); do \
		echo "=== Cleaning $$dir ==="; \
		if [ -n "$(BUILD_ROOT)" ]; then \
			$(MAKE) -C $$dir BUILD_DIR="$(BUILD_ROOT)/$$dir" clean || exit 1; \
		else \
			$(MAKE) -C $$dir clean || exit 1; \
		fi; \
	done

.PHONY: all native install clean $(SUBDIRS)

test-security-stack:
	bash tests/security/run.sh

.PHONY: test-security-stack

