// xAuth keychain: shows the current 8-digit code on the OLED.
//
// This file wires the modules together and owns nothing else. The OTP math and
// the device key live in totp.cpp, the panel lives in display.cpp, the time
// source lives in clock.cpp.

#include <Arduino.h>
#include <Wire.h>

#include "clock.hpp"
#include "display.hpp"
#include "totp.hpp"

// I2C bus, shared by the OLED and (next) the DS3231. Owned here rather than by
// either device, since Wire.begin() must happen exactly once.
#define PIN_SDA 4
#define PIN_SCL 5

void setup() {
    Serial.begin(115200);
    Wire.begin(PIN_SDA, PIN_SCL);

    clock_begin();

    if (!display_begin()) {
        Serial.println("OLED not found on the I2C bus -- check wiring and address.");
        for (;;) { delay(1000); }
    }
}

void loop() {
    char code[OTP_DIGITS + 1];
    format_code(otp_now(clock_now()), code);
    display_show_code(code);
    display_ln();
    display_message("ID: KJTJ");
}
