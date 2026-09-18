// OTP generation. The math here is byte-for-byte the same as the server's
// core/otp.cpp -- if the two ever disagree, every code this keychain shows is
// rejected and nothing tells you why. Do not "clean up" one side in isolation.

#include "totp.hpp"
#include "securekey.hpp"

#include <Arduino.h>
#include <string.h>
#include <mbedtls/md.h>   // BearSSL equivalent on the ESP32-C3
#include <mbedtls/platform_util.h>

#ifndef DEVICE_ID
#error "securekey.hpp has no DEVICE_ID -- regenerate it with: provision add --firmware-header include/securekey.hpp"
#endif

// Module-private on purpose: the key never leaves this translation unit.
static const char* secretKey = SECURE_KEY;

uint32_t dynamic_truncate(const uint8_t* hmac, int digits) {
    // Get last nibble as offset (0 to 15)
    int offset = hmac[31] & 0x0F;

    // Extract 4 bytes starting from offset
    uint32_t bin_code = ((hmac[offset]     & 0x7F) << 24) |
                         ((hmac[offset + 1] & 0xFF) << 16) |
                         ((hmac[offset + 2] & 0xFF) << 8)  |
                          (hmac[offset + 3] & 0xFF);

    uint32_t mod = 1;
    for (int i = 0; i < digits; i++) mod *= 10;

    return bin_code % mod;
}

uint32_t totp(const char* key, time_t now, int step_seconds, int digits) {
    uint64_t counter = static_cast<uint64_t>(now) / step_seconds;
    size_t key_len = strlen(key);

    // Convert counter into 8-byte big-endian format
    uint8_t counter_bytes[8];
    for (int i = 7; i >= 0; i--) {
        counter_bytes[i] = counter & 0xFF;
        counter >>= 8;
    }

    // Allocate 32 bytes for SHA256 output hash array
    uint8_t hmacResult[32];

    // mbedTLS Context Setup za ESP32
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    
    // Inicijalizacija SHA256 strukture
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    
    // Pokretanje HMAC operacije sa ključem
    mbedtls_md_hmac_starts(&ctx, (const unsigned char*)key, key_len);
    mbedtls_md_hmac_update(&ctx, counter_bytes, 8);
    mbedtls_md_hmac_finish(&ctx, hmacResult);
    
    // Čišćenje memorije konteksta
    mbedtls_md_free(&ctx);

    uint32_t code = dynamic_truncate(hmacResult, digits);
    // The HMAC is key-derived; don't leave it on the stack.
    mbedtls_platform_zeroize(hmacResult, sizeof hmacResult);
    return code;
}

uint32_t otp_now(time_t now) {
    return totp(secretKey, now);
}

const char* device_id() {
    return DEVICE_ID;
}

uint32_t otp_seconds_left(uint32_t now) {
    return OTP_STEP_SECONDS - (now % OTP_STEP_SECONDS);
}

void format_code(uint32_t code, char* out) {
    // snprintf, not manual division: the leading zeros are part of the code.
    snprintf(out, OTP_DIGITS + 1, "%0*lu", OTP_DIGITS, (unsigned long)code);
}
