# ExamOS Master Native C/C++ Build Makefile

SUBDIRS = kiosk/launcher agent proctoring server
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

.PHONY: all install clean $(SUBDIRS)
