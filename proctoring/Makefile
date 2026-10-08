CXX ?= g++
CXXFLAGS ?= -Wall -Wextra -O2 -std=c++17 -Iinclude -D_FORTIFY_SOURCE=2 -fstack-protector-strong
LDFLAGS ?= -lpthread -lm

SRCS = main.cpp \
       client/media_capture.cpp \
       analysis/anomaly_detector.cpp

OBJS = $(SRCS:.cpp=.o)
TARGET = examos-proctor

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

install: $(TARGET)
	install -d $(DESTDIR)/usr/local/bin
	install -m 755 $(TARGET) $(DESTDIR)/usr/local/bin/

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all install clean
