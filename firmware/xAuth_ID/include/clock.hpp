#pragma once

#include <time.h>

// Time source for the OTP counter.
//
// Today this seeds the ESP32's internal clock from the build timestamp that
// sync_time.py injects, which means the time is only correct until the first
// reboot away from the host. The DS3231 replaces this: clock_begin() will read
// the RTC and refuse to run when its oscillator-stop flag says the time is not
// trustworthy. Everything above this header calls clock_now() either way.
void   clock_begin();
time_t clock_now();
