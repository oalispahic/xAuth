# Host builds. The ESP8266 firmware is built separately with PlatformIO --
# see firmware/xAuth_ID.

CXX      ?= c++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -O2

# macOS ships an ancient LibreSSL and no openssl headers; Homebrew's openssl@3
# is keg-only, so it has to be pointed at explicitly. On Linux this resolves to
# empty and the system paths are used.
#
# Portability caveat: Homebrew's libcrypto carries an absolute install name, so
# these binaries hardcode /opt/homebrew/... and will not run on a machine
# without that exact path. Check with `otool -L build/verifier`. There is no
# flag that fixes this -- the Phase 10 container has to build its own binary
# inside the image (or link libcrypto statically). Fine for local dev, not
# something to ship.
OPENSSL_PREFIX := $(shell brew --prefix openssl@3 2>/dev/null)
ifneq ($(OPENSSL_PREFIX),)
CPPFLAGS += -I$(OPENSSL_PREFIX)/include
LDFLAGS  += -L$(OPENSSL_PREFIX)/lib
endif

LDLIBS += -lcrypto -lsqlite3

# Absolute fallback path to the keystore, so a dev build works from any working
# directory instead of only from the repo root. $XAUTH_DB overrides it at run
# time, which is how the container build is expected to point at its mount.
CPPFLAGS += -DXAUTH_DB_DEFAULT='"$(abspath db/auth)"' 

BUILD := build
CORE  := core/otp.cpp core/keystore.cpp

.PHONY: all clean db test

all: $(BUILD)/verifier $(BUILD)/provision

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/verifier: verifier/main.cpp $(CORE) | $(BUILD)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

$(BUILD)/provision: tools/provision/main.cpp $(CORE) | $(BUILD)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

$(BUILD)/otpgen: tests/gen_codes.cpp $(CORE) | $(BUILD)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

# Cross-checks core/otp.cpp against the independent Python implementation and
# the golden vectors. The firmware's BearSSL copy must match these too.
test: $(BUILD)/otpgen
	python3 tests/check_vectors.py

# Create an empty keystore from the schema. Refuses to clobber an existing one --
# the keystore is the one piece of state that cannot be regenerated.
db:
	@test ! -f db/auth || { echo "db/auth already exists; refusing to overwrite."; exit 1; }
	sqlite3 db/auth < db/schema.sql
	chmod 0600 db/auth
	@echo "Created db/auth"

clean:
	rm -rf $(BUILD)
