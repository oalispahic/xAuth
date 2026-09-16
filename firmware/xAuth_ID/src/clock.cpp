#include "clock.hpp"

#include <Arduino.h>
#include <sys/time.h>

void clock_begin() {
    // Drain anything the host left in the buffer, then give it a moment to
    // attach before the first output.
    while (Serial.available()) { Serial.read(); }
    delay(3000);
    Serial.println("Time syncing... Please wait for the READY signal from the computer.\n");

    // COMPILER_UNIX_TIME is injected at build time by sync_time.py.
    //
    // This runs on every boot, so the clock resets to whenever the firmware was
    // compiled each time the device is powered up. That is fine on the bench
    // with USB attached and wrong everywhere else. The DS3231 fixes it.
    time_t unixtimenow = COMPILER_UNIX_TIME;

    struct timeval tv = { .tv_sec = unixtimenow, .tv_usec = 0 };
    settimeofday(&tv, nullptr);
}

time_t clock_now() {
    return time(nullptr);
}
