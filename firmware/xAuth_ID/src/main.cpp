// xAuth keychain: shows the current 8-digit code on the OLED.
//
// This file wires the modules together and owns nothing else. The OTP math,
// the device key and the device ID live in totp.cpp, the panel lives in
// display.cpp, the clock (DS3231) lives in clock.cpp.

#include <Arduino.h>
#include <Wire.h>

#include "clock.hpp"
#include "display.hpp"
#include "totp.hpp"

// I2C bus, shared by the OLED (0x3C) and the DS3231 (0x68). Owned here rather
// than by either device, since Wire.begin() must happen exactly once.
#define PIN_SDA 4
#define PIN_SCL 5

void setup() {
    Serial.begin(115200);
    Wire.begin(PIN_SDA, PIN_SCL);

    if (!display_begin()) {
        Serial.println("OLED not found on the I2C bus -- check wiring and address.");
        for (;;) { delay(1000); }
    }

    ClockState s = clock_begin();
    if (s != ClockState::Ok) {
        // No code is shown until the time is set with tools/rtc_sync.py. A
        // code from a wrong clock would be rejected anyway, and quietly
        // showing it would hide the real problem.
        Serial.printf("clock not trusted: %s -- run `pio run -t rtc_set`\n", clock_state_text(s));
    }
}

void loop() {
    // Always serviced, so the time can be set whatever the display shows.
    clock_poll_serial();

    static uint32_t last_drawn = 0;
    static ClockState last_state = ClockState::NoRtc;

    ClockState s = clock_state();
    uint32_t now = (s == ClockState::NoRtc) ? 0 : clock_now();
    s = clock_state();   // clock_now() can demote a clock that went backwards

    if (now != last_drawn || s != last_state) {
        if (s == ClockState::Ok) {
            char code[OTP_DIGITS + 1];
            format_code(otp_now(now), code);
            display_show_code(code, device_id(), otp_seconds_left(now), OTP_STEP_SECONDS);
            memset(code, 0, sizeof code);
        } else {
            display_status(clock_state_text(s), device_id());
        }
        last_drawn = now;
        last_state = s;
    }
    delay(50);
}
