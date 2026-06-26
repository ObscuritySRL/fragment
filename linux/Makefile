# Plain-make build, for hosts without CMake. `make` builds Release artifacts in
# build/; `make DEBUG=1` builds the chatty debug variant. Mirrors build.sh.
CC      ?= cc
BUILD   ?= build
CSTD    := -std=c17

ifdef DEBUG
OPT     := -O0 -g -DDEBUG
else
OPT     := -O2
endif

ARCH    := $(shell uname -m)
ifneq (,$(filter aarch64 arm64,$(ARCH)))
BP      := -mbranch-protection=standard
endif

LIB     := $(BUILD)/libfragment.so
CLI     := $(BUILD)/fragment

.PHONY: all clean
all: $(LIB) $(CLI)

$(LIB): main.c curl.h util.h log.h config.h hook.h | $(BUILD)
	$(CC) $(OPT) $(CSTD) -fPIC -fvisibility=hidden $(BP) -shared main.c -o $@ -ldl -lpthread -Wl,-z,nodelete

$(CLI): tools/fragment.c | $(BUILD)
	$(CC) $(OPT) $(CSTD) tools/fragment.c -o $@ -ldl

$(BUILD):
	mkdir -p $(BUILD)

clean:
	rm -rf $(BUILD)
