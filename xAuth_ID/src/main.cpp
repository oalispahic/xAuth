#include <Arduino.h>
#include <time.h>
#include <sys/time.h>
#include <BearSSLHelpers.h>
#include "../include/securekey.hpp"

#define LED1 D4
#define LED2 D0


const char* secretKey = SECURE_KEY;

// RFC 4226 Dynamic Truncation
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

uint32_t totp(const char* key, time_t now, int step_seconds = 90, int digits = 8) {
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

    // BearSSL Context Setup using raw C pointers
    br_hmac_key_context kc;
    br_hmac_key_init(&kc, &br_sha256_vtable, key, key_len);
    
    br_hmac_context hc;
    br_hmac_init(&hc, &kc, 0);
    br_hmac_update(&hc, counter_bytes, 8); 
    br_hmac_out(&hc, hmacResult);

    return dynamic_truncate(hmacResult, digits);
}

void setTime(){
time_t unixtimenow = COMPILER_UNIX_TIME;

    // Inject directly into internal hardware clock
    struct timeval tv = { .tv_sec = unixtimenow, .tv_usec = 0 };
    settimeofday(&tv, nullptr);
}

void setup() {
  Serial.begin(115200);

   while(Serial.available()) { Serial.read(); }
   delay(3000);
   Serial.println("Time syncing... Please wait for the READY signal from the computer.\n"); 

   setTime();
   
}


void loop() {

    time_t now = time(nullptr);
    uint32_t code = totp(secretKey, now);

    int first_four = code / 10000;
  int second_four = code % 10000;
  
  Serial.print("Time: ");
  Serial.print(now);
  Serial.print(" | Code: ");
  Serial.print(first_four);
  Serial.print(" - ");
  Serial.println(second_four);

  delay(5000);

  
}

