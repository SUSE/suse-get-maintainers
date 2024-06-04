ARCH := $(shell uname -p)
CXX = g++
CXXFLAGS=-O3 -std=c++20 -fPIE -g -Wall -Wextra -Wno-dangling-else -Wno-unused-function
ifeq ($(ARCH),x86_64)
CXXFLAGS+=-march=x86-64-v2
endif

TARGET=suse-add-cves

all: $(TARGET)

sanitize: CXXFLAGS+=-fsanitize=address,undefined -ggdb3
sanitize: all

debug: CXXFLAGS+=-O0 -ggdb3
debug: all

%.d: %.cc
	${CXX} -MM -c $(CXXFLAGS) $< > $@

$(TARGET): $(TARGET).o
	${CXX} -o $@ $(CXXFLAGS) $+ -lgit2 -lcurl

clean:
	rm -f $(TARGET) *.o

.PHONY: clean
