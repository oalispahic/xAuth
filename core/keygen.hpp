#pragma once

#include <string>

// Device ID and key generation, shared by the provisioning CLI and the admin
// daemon so there is exactly one definition of what a valid new device is.

// Crockford Base32 ID of `length` characters, from the CSPRNG. Throws on
// RAND_bytes failure.
std::string generate_device_id(int length);

// 64 random bytes as 128 lowercase hex characters. The ASCII hex text is the
// HMAC key on both the server and the firmware -- keep the format.
std::string generate_key();

// Labels land on terminals, in SQL and in a C string literal in the firmware
// header: 1-64 printable ASCII, no quotes or backslashes.
bool valid_label(const std::string& s);

// The C++ header the keychain firmware is built from.
std::string firmware_header(const std::string& id, const std::string& key);
