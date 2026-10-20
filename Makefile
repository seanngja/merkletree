CC = cc
PYTHON ?= python3
BUILD ?= build
CPPFLAGS += -Iinclude
CFLAGS ?= -O2 -g
CFLAGS += -std=c17 -Wall -Wextra -Wpedantic -Wconversion -Wshadow
LDLIBS += -lcrypto

# Optional local development package; otherwise use system OpenSSL headers/libs.
OPENSSL_PREFIX ?= $(if $(wildcard .deps/usr/include/openssl/evp.h),$(CURDIR)/.deps/usr)
ifneq ($(strip $(OPENSSL_PREFIX)),)
MULTIARCH := $(shell $(CC) -dumpmachine)
CPPFLAGS += -I"$(OPENSSL_PREFIX)/include" -I"$(OPENSSL_PREFIX)/include/$(MULTIARCH)"
OPENSSL_LDFLAGS = -L"$(OPENSSL_PREFIX)/lib/$(MULTIARCH)" -L"$(OPENSSL_PREFIX)/lib"
endif

LIB_OBJECTS = $(BUILD)/merkle.o $(BUILD)/sha256.o

.PHONY: all test sanitize clean
all: $(BUILD)/merkle_baseline

$(BUILD):
	mkdir -p $@

$(BUILD)/%.o: src/%.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

$(BUILD)/merkle_baseline: $(BUILD)/main.o $(LIB_OBJECTS)
	$(CC) $(LDFLAGS) $(OPENSSL_LDFLAGS) $^ $(LDLIBS) -o $@

$(BUILD)/test_merkle: tests/test_merkle.c $(LIB_OBJECTS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(OPENSSL_LDFLAGS) $^ $(LDLIBS) -o $@

# GNU-compatible linker wrappers inject allocation and hashing failures.
$(BUILD)/test_alloc: tests/test_alloc.c $(LIB_OBJECTS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(OPENSSL_LDFLAGS) $^ \
		-Wl,--wrap=malloc -Wl,--wrap=free -Wl,--wrap=sha256_digest $(LDLIBS) -o $@

test: $(BUILD)/merkle_baseline $(BUILD)/test_merkle $(BUILD)/test_alloc
	$(BUILD)/test_merkle
	$(BUILD)/test_alloc
	$(PYTHON) tests/test_reference.py $(BUILD)/merkle_baseline

sanitize:
	$(MAKE) BUILD=build-sanitize \
		CFLAGS="-O1 -g -std=c17 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -fsanitize=address,undefined -fno-omit-frame-pointer -fno-pie" \
		LDFLAGS="-fsanitize=address,undefined -no-pie" test

clean:
	$(RM) -r build build-sanitize

-include $(wildcard $(BUILD)/*.d)
