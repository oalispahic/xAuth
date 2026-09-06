#include <Arduino.h>
#include <time.h>
#include <sys/time.h>
#include <mbedtls/md.h> // Zamjena za BearSSL (mbedTLS je integrisan u ESP32)
#include "../include/securekey.hpp"

// Na ESP32-C3 koristite direktne GPIO brojeve umjesto D0/D4 oznaka
#define LED1 4  // Prilagodite GPIO broj vašoj ploči
#define LED2 5  // Prilagodite GPIO broj vašoj ploči

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

    return dynamic_truncate(hmacResult, digits);
}

void setTime(){ 
    // Napomena: COMPILER_UNIX_TIME mora biti definisan u platformio.ini kao build_flags
    time_t unixtimenow = COMPILER_UNIX_TIME; 

    // Direktno ubacivanje u interni sat ESP32 hardvera
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

   /*/ int first_four = code / 10000;
    int second_four = code % 10000;
  
    Serial.print("Time: ");
    Serial.print(now);
    Serial.print(" | Code: ");
    
    // Dodano formatiranje sa vodećim nulama ako je kod manji od 4 cifre
    if (first_four < 1000) Serial.print("0");
    if (first_four < 100) Serial.print("0");
    if (first_four < 10) Serial.print("0");
    Serial.print(first_four);
    
    Serial.print(" - ");
    
    if (second_four < 1000) Serial.print("0");
    if (second_four < 100) Serial.print("0");
    if (second_four < 10) Serial.print("0");
    Serial.println(second_four);

    delay(5000);*/
  
    Serial.println("Time: ");
    Serial.println(now);
    delay(500);
}
