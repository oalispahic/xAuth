#pragma once

#include <stdint.h>

// Time source for the OTP counter: the DS3231, and only the DS3231. The ESP32's
// own clock drifts badly and is never used -- two clocks means two answers.
//
// The time is only trusted when three independent checks agree (see
// clock_begin): the RTC's oscillator-stop flag is clear, this device has been
// set up before (a flag in NVS), and the time is neither before the firmware
// was built nor before the latest time this device has already seen. An
// untrusted clock shows no codes until it is set over USB with
// tools/rtc_sync.py.

enum class ClockState {
    Ok,             // trusted
    NoRtc,          // DS3231 not on the I2C bus
    Stopped,        // oscillator stopped (new chip, dead battery) or time before the build
    NeverSet,       // this ESP32 has never been given the time
    WentBackwards,  // earlier than a time this device has already seen
};

// Call once, after Wire.begin(). Returns the boot-time verdict.
ClockState clock_begin();

// Current state. Becomes Ok after a successful set over serial.
ClockState clock_state();

// Short text for the display when the state is not Ok, e.g. "SET TIME".
const char* clock_state_text(ClockState s);

// Unix time from the RTC, UTC. Only meaningful when clock_state() is Ok.
uint32_t clock_now();

// Handles the USB serial time protocol. Never blocks; call from loop().
//   "?"         -> "NOW t=<epoch> osf=<0|1> temp=<C> state=<name>"
//   "T <epoch>" -> "SET ..." or "ERR rejected"
void clock_poll_serial();
