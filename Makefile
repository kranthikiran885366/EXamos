# ExamOS Master Native C/C++ Build Makefile

SUBDIRS = kiosk/launcher agent proctoring server

all:
	@for dir in $(SUBDIRS); do \
		echo "=== Building $$dir ==="; \
		$(MAKE) -C $$dir all || exit 1; \
	done
	@echo "=== All ExamOS Native Subsystems Built Successfully ==="

install:
	@for dir in $(SUBDIRS); do \
		echo "=== Installing $$dir ==="; \
		$(MAKE) -C $$dir install || exit 1; \
	done

clean:
	@for dir in $(SUBDIRS); do \
		echo "=== Cleaning $$dir ==="; \
		$(MAKE) -C $$dir clean || true; \
	done

.PHONY: all install clean $(SUBDIRS)
