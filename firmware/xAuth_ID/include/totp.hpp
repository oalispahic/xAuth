#pragma once

#include <stdint.h>
#include <time.h>

// OTP parameters. These must match the server side exactly (core/otp.hpp) --
// a keychain and a verifier that disagree on the step or the digit count will
// never produce the same code, and the failure looks like a clock problem.
#define OTP_STEP_SECONDS 90
#define OTP_DIGITS       8

// RFC 4226 dynamic truncation over a 32-byte HMAC-SHA256 result.
uint32_t dynamic_truncate(const uint8_t* hmac, int digits);

// Code for an arbitrary key. Exposed for bench testing against known vectors.
uint32_t totp(const char* key,
              time_t now,
              int step_seconds = OTP_STEP_SECONDS,
              int digits       = OTP_DIGITS);

// Code for *this* device. The key stays inside totp.cpp and is never handed
// out, so nothing else in the firmware ever holds a pointer to it.
uint32_t otp_now(time_t now);

// This device's public ID, from the same provisioning run as its key
// (`provision add --firmware-header include/securekey.hpp`).
const char* device_id();

// Seconds left before the code changes.
uint32_t otp_seconds_left(uint32_t now);

// Zero-pads to OTP_DIGITS and NUL-terminates. `out` must hold OTP_DIGITS + 1
// bytes. A code with leading zeros is still an 8-digit code; printing the
// uint32_t directly drops them and the server rejects what you typed.
void format_code(uint32_t code, char* out);
