#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <ctime>

// Single source of truth for the OTP math. The firmware in firmware/xAuth_ID
// necessarily carries its own BearSSL copy of this; the two must produce
// identical codes for identical (key, counter). Anything changed here has to be
// mirrored there and re-validated against tests/vectors.

#define OTP_SIZE 8
#define OTP_STEP_SECONDS 90

std::vector<unsigned char> hmac_sha256(const std::string& key,
                                       const unsigned char* msg, size_t msg_len);

uint32_t dynamic_truncate(const std::vector<unsigned char>& hmac, int digits);

// The HMAC counter for a wall-clock time. Exposed separately from totp() so the
// verifier can walk counter-1 / counter / counter+1 for clock drift.
uint64_t counter_for_time(time_t now, int step_seconds = OTP_STEP_SECONDS);

uint32_t totp_for_counter(const std::string& key, uint64_t counter,
                          int digits = OTP_SIZE);

uint32_t totp(const std::string& key, time_t now,
              int step_seconds = OTP_STEP_SECONDS, int digits = OTP_SIZE);

std::string pad_and_convert(uint32_t code);
