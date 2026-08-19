#include "otp.hpp"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <iomanip>
#include <sstream>
#include <stdexcept>

std::vector<unsigned char> hmac_sha256(const std::string& key,
                                        const unsigned char* msg, size_t msg_len) {
    unsigned char* digest;
    unsigned int len = EVP_MAX_MD_SIZE;
    std::vector<unsigned char> out(EVP_MAX_MD_SIZE);

    digest = HMAC(EVP_sha256(),
                  key.data(), key.size(),
                  msg, msg_len,
                  out.data(), &len);

    if (!digest) throw std::runtime_error("HMAC failed");
    out.resize(len);
    return out;
}

uint32_t dynamic_truncate(const std::vector<unsigned char>& hmac, int digits) {
    int offset = hmac.back() & 0x0F;

    uint32_t bin_code = ((hmac[offset]     & 0x7F) << 24) |
                         ((hmac[offset + 1] & 0xFF) << 16) |
                         ((hmac[offset + 2] & 0xFF) << 8)  |
                          (hmac[offset + 3] & 0xFF);

    uint32_t mod = 1;
    for (int i = 0; i < digits; i++) mod *= 10;

    return bin_code % mod;
}

uint64_t counter_for_time(time_t now, int step_seconds) {
    return static_cast<uint64_t>(now) / step_seconds;
}

uint32_t totp_for_counter(const std::string& key, uint64_t counter, int digits) {
    // counter must be big-endian 8 bytes
    unsigned char counter_bytes[8];
    for (int i = 7; i >= 0; i--) {
        counter_bytes[i] = counter & 0xFF;
        counter >>= 8;
    }

    auto mac = hmac_sha256(key, counter_bytes, 8);
    return dynamic_truncate(mac, digits);
}

uint32_t totp(const std::string& key, time_t now, int step_seconds, int digits) {
    return totp_for_counter(key, counter_for_time(now, step_seconds), digits);
}

std::string pad_and_convert(uint32_t code) {
    std::ostringstream oss;
    oss << std::setfill('0') << std::setw(OTP_SIZE) << code;
    std::string computed_code = oss.str();
    return computed_code;
}
