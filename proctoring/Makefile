CXX ?= g++
OPENCV_CFLAGS ?= $(shell pkg-config --cflags opencv4 2>/dev/null)
OPENCV_LIBS ?= $(shell pkg-config --libs opencv4 2>/dev/null)
CXXFLAGS ?= -Wall -Wextra -O2 -std=c++17 -Iinclude -D_FORTIFY_SOURCE=2 -fstack-protector-strong
CXXFLAGS += $(OPENCV_CFLAGS)
LDFLAGS ?= -lcurl -lpthread -lm $(OPENCV_LIBS) -lcrypto

SRCS = main.cpp \
       client/media_capture.cpp \
       analysis/vision_engine.cpp

BUILD_DIR ?= .
COMMON_OBJ = $(BUILD_DIR)/common/examos_appliance.o
OBJS = $(addprefix $(BUILD_DIR)/,$(SRCS:.cpp=.o)) $(COMMON_OBJ)
OBJECT_ARGS = $(foreach object,$(OBJS),"$(object)")
TARGET = $(BUILD_DIR)/examos-proctor

all: $(TARGET)

$(TARGET): $(OBJS)
	@mkdir -p "$(@D)"
	$(CXX) $(CXXFLAGS) -o "$(TARGET)" $(OBJECT_ARGS) $(LDFLAGS)

$(BUILD_DIR)/%.o: %.cpp
	@mkdir -p "$(@D)"
	$(CXX) $(CXXFLAGS) -c "$<" -o "$@"

# The appliance identity check is shared by the server, the agent and the
# proctoring worker. It is C, and is compiled as C++ here.
$(COMMON_OBJ): ../common/examos_appliance.c ../common/include/examos_appliance.h
	@mkdir -p "$(@D)"
	$(CXX) $(CXXFLAGS) -I../common/include -x c++ -c "$<" -o "$@"

install: $(TARGET)
	install -d $(DESTDIR)/usr/local/bin
	install -m 755 "$(TARGET)" $(DESTDIR)/usr/local/bin/

test-vision-engine: $(BUILD_DIR)/analysis/vision_engine.o
	@set -eu; test_binary=$$(mktemp "$${TMPDIR:-/tmp}/examos-vision-test.XXXXXX"); \
	trap 'rm -f -- "$$test_binary"' EXIT; \
	$(CXX) $(CXXFLAGS) -I../proctoring/include ../tests/p4/vision-engine-test.cpp \
		$(BUILD_DIR)/analysis/vision_engine.o $(LDFLAGS) -o "$$test_binary"; \
	"$$test_binary" \
		"$$(pwd)/models/MODEL-MANIFEST.json" \
		"$$(pwd)/../tests/p4/fixtures/portrait-pd-usgov.jpg" \
		"$$(pwd)/../tests/p4/fixtures/blank-frame.png"

clean:
	rm -f $(OBJECT_ARGS) "$(TARGET)"

.PHONY: all install clean test-vision-engine
