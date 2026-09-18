# Host builds for Linux and macOS. The ESP32-C3 firmware is built separately
# with PlatformIO -- see firmware/xAuth_ID.
#
# Build dependencies:
#   Debian/Ubuntu  apt install build-essential pkg-config libssl-dev libsqlite3-dev sqlite3 python3
#   Fedora/RHEL    dnf install gcc-c++ make pkgconf-pkg-config openssl-devel sqlite-devel sqlite python3
#   Arch           pacman -S base-devel pkgconf openssl sqlite python
#   macOS          xcode-select --install && brew install openssl@3
#
# Run `make deps` to see what this machine resolved to.

CXX      ?= c++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -O2
# The verifier serves each connection on its own thread.
CXXFLAGS += -pthread
LDFLAGS  += -pthread

UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
# macOS ships LibreSSL's dylib with no headers, and the SDK's sqlite3 is fine.
# Homebrew's openssl@3 is keg-only, so it has to be pointed at explicitly.
# `brew --prefix` covers both /opt/homebrew (Apple Silicon) and /usr/local
# (Intel).
#
# Portability caveat: Homebrew's libcrypto carries an absolute install name, so
# these binaries hardcode the Homebrew path and will not run on a machine
# without it. Check with `otool -L build/verifier`. Fine for local dev; the
# Phase 10 container builds its own binary on Linux.
# Resolved once: `?=` would re-run brew, which is slow, on every expansion.
ifeq ($(origin OPENSSL_PREFIX),undefined)
OPENSSL_PREFIX := $(shell brew --prefix openssl@3 2>/dev/null)
endif
# Only targets that compile need it, so `make clean` and friends still work.
ifneq ($(filter-out clean db deps,$(or $(MAKECMDGOALS),all)),)
ifeq ($(wildcard $(OPENSSL_PREFIX)/include/openssl/evp.h),)
$(error OpenSSL 3 headers not found. Run `brew install openssl@3`, or pass OPENSSL_PREFIX=/path/to/openssl)
endif
endif
CPPFLAGS += -I$(OPENSSL_PREFIX)/include
LDFLAGS  += -L$(OPENSSL_PREFIX)/lib
LDLIBS   += -lcrypto -lsqlite3
else
# Linux and other Unixes: ask pkg-config, which knows each distro's layout.
# Without it, the libraries are assumed to be on the default search paths,
# which holds for every mainstream distro's -dev packages.
PKG_CONFIG ?= pkg-config
ifeq ($(shell $(PKG_CONFIG) --exists libcrypto sqlite3 2>/dev/null && echo yes),yes)
CPPFLAGS += $(shell $(PKG_CONFIG) --cflags libcrypto sqlite3)
LDLIBS   += $(shell $(PKG_CONFIG) --libs libcrypto sqlite3)
else
LDLIBS   += -lcrypto -lsqlite3
endif
endif

# Absolute fallback path to the keystore, so a dev build works from any working
# directory instead of only from the repo root. $XAUTH_DB overrides it at run
# time, which is how the container build is expected to point at its mount.
CPPFLAGS += -DXAUTH_DB_DEFAULT='"$(abspath db/auth)"'

PYTHON ?= python3

BUILD := build
CORE  := core/otp.cpp core/keystore.cpp
HDRS  := core/otp.hpp core/keystore.hpp

.PHONY: all clean db test test-verifier devcode deps

all: $(BUILD)/verifier $(BUILD)/provision

$(BUILD):
	mkdir -p $(BUILD)

# Headers are listed as prerequisites so editing one triggers a rebuild, but
# filtered out of the compile line.
$(BUILD)/verifier: verifier/main.cpp $(CORE) $(HDRS) | $(BUILD)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(filter %.cpp,$^) -o $@ $(LDFLAGS) $(LDLIBS)

$(BUILD)/provision: tools/provision/main.cpp $(CORE) $(HDRS) | $(BUILD)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(filter %.cpp,$^) -o $@ $(LDFLAGS) $(LDLIBS)

# DEV ONLY: prints a device's current code from the keystore. Deliberately not
# in `all`, so it never ends up on the server by accident.
devcode: $(BUILD)/devcode
$(BUILD)/devcode: tools/devcode/main.cpp $(CORE) $(HDRS) | $(BUILD)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(filter %.cpp,$^) -o $@ $(LDFLAGS) $(LDLIBS)

$(BUILD)/otpgen: tests/gen_codes.cpp $(CORE) $(HDRS) | $(BUILD)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(filter %.cpp,$^) -o $@ $(LDFLAGS) $(LDLIBS)

# Cross-checks core/otp.cpp against the independent Python implementation and
# the golden vectors. The firmware's mbedTLS copy must match these too.
test: $(BUILD)/otpgen
	$(PYTHON) tests/check_vectors.py

# Table-driven cases against a live verifier on a throwaway keystore.
test-verifier: $(BUILD)/verifier $(BUILD)/provision
	$(PYTHON) tests/verifier_cases.py

# Create an empty keystore from the schema. Refuses to clobber an existing one --
# the keystore is the one piece of state that cannot be regenerated.
db:
	@test ! -f db/auth || { echo "db/auth already exists; refusing to overwrite."; exit 1; }
	sqlite3 db/auth < db/schema.sql
	chmod 0600 db/auth
	@echo "Created db/auth"

# Print what the build resolved to, and check the tools the other targets need.
deps:
	@echo "platform   $(UNAME_S)"
	@echo "compiler   $$($(CXX) --version | head -n 1)"
	@echo "CPPFLAGS   $(CPPFLAGS)"
	@echo "LDFLAGS    $(LDFLAGS)"
	@echo "LDLIBS     $(LDLIBS)"
	@for tool in sqlite3 $(PYTHON); do \
		command -v $$tool >/dev/null 2>&1 \
			&& echo "found      $$tool" \
			|| echo "MISSING    $$tool"; \
	done

clean:
	rm -rf $(BUILD)
