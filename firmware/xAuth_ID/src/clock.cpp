#include "clock.hpp"

#include <Arduino.h>
#include <Preferences.h>
#include <RTClib.h>
#include <stdlib.h>
#include <string.h>

// Firmware cannot run before it was compiled, so any earlier time is garbage.
// Injected by sync_time.py. It is a floor, never the time to set.
static const uint32_t BUILD_EPOCH = COMPILER_UNIX_TIME;

// A trusted clock accepts a nudge, never a jump. The DS3231 drifts about a
// minute a year, so five minutes covers any honest correction. Without this,
// anyone with the keychain and a USB cable could move the clock forward, read
// future codes, move it back and return the keychain.
static const int32_t MAX_NUDGE_SECONDS = 300;

// High-water mark writes: at most every 6 hours, or one NVS sector would take
// ~350,000 writes a year.
static const uint32_t HIGH_WATER_INTERVAL = 6 * 3600;

// 2100-01-01. Nothing legitimate is later; the DS3231 only counts to 2099.
static const unsigned long MAX_EPOCH = 4102444800UL;

static RTC_DS3231  rtc;
static Preferences prefs;
static ClockState  state = ClockState::NoRtc;
// The high-water mark, mirrored in RAM: clock_now() runs many times a second
// and must not hit NVS each time.
static uint32_t    last_seen = 0;

static ClockState evaluate() {
    if (!rtc.begin())    return ClockState::NoRtc;
    if (rtc.lostPower()) return ClockState::Stopped;    // OSF, reg 0x0F bit 7
    if (!prefs.getBool("provisioned", false)) return ClockState::NeverSet;

    uint32_t now = rtc.now().unixtime();
    if (now < BUILD_EPOCH) return ClockState::Stopped;
    if (now < last_seen)   return ClockState::WentBackwards;
    return ClockState::Ok;
}

ClockState clock_begin() {
    prefs.begin("xauth", false);
    last_seen = prefs.getUInt("last_seen", 0);
    state = evaluate();
    if (state != ClockState::NoRtc) {
        // Not needed, and the square wave costs battery.
        rtc.disable32K();
        rtc.writeSqwPinMode(DS3231_OFF);
    }
    return state;
}

ClockState clock_state() { return state; }

const char* clock_state_text(ClockState s) {
    switch (s) {
        case ClockState::Ok:            return "OK";
        case ClockState::NoRtc:         return "NO CLOCK";
        case ClockState::Stopped:       return "SET TIME";
        case ClockState::NeverSet:      return "SET TIME";
        case ClockState::WentBackwards: return "CLOCK ERROR";
    }
    return "?";
}

static const char* state_name(ClockState s) {
    switch (s) {
        case ClockState::Ok:            return "ok";
        case ClockState::NoRtc:         return "no_rtc";
        case ClockState::Stopped:       return "stopped";
        case ClockState::NeverSet:      return "never_set";
        case ClockState::WentBackwards: return "went_backwards";
    }
    return "?";
}

static void set_high_water(uint32_t t) {
    last_seen = t;
    prefs.putUInt("last_seen", t);
}

static void remember_time(uint32_t now) {
    if (now > last_seen + HIGH_WATER_INTERVAL) set_high_water(now);
}

uint32_t clock_now() {
    uint32_t now = rtc.now().unixtime();
    if (state == ClockState::Ok) {
        // Checked on every read, not just at boot: a clock that jumps
        // backwards while running is as untrustworthy as one that booted wrong.
        if (now < last_seen) {
            state = ClockState::WentBackwards;
        } else {
            remember_time(now);
        }
    }
    return now;
}

static bool apply_time(uint32_t epoch) {
    if (state == ClockState::NoRtc) return false;
    if (epoch < BUILD_EPOCH) return false;

    if (state == ClockState::Ok) {
        int64_t delta = (int64_t)epoch - (int64_t)rtc.now().unixtime();
        if (delta < -MAX_NUDGE_SECONDS || delta > MAX_NUDGE_SECONDS) return false;
    }

    // The high-water mark never moves back by more than a nudge, whatever
    // state the clock is in. Otherwise: pull the battery (OSF set, clock
    // untrusted), set the clock a week ahead, read a week of codes, pull the
    // battery again and set it back -- and nothing would show. With this rule
    // the device stays a week ahead, every login fails, and the owner finds
    // out. Resetting a genuinely wrong mark is a deliberate act:
    // `pio run -t erase` wipes NVS.
    if ((int64_t)epoch < (int64_t)last_seen - MAX_NUDGE_SECONDS) return false;

    // Explicit uint32_t: a bare integer can pick DateTime's y/m/d constructor.
    rtc.adjust(DateTime((uint32_t)epoch));    // also clears OSF
    prefs.putBool("provisioned", true);
    if (epoch > last_seen) set_high_water(epoch);
    state = evaluate();
    return state == ClockState::Ok;
}

static void report(const char* tag) {
    bool rtc_ok = state != ClockState::NoRtc;
    Serial.printf("%s t=%lu osf=%d temp=%.2f state=%s\n", tag,
                  rtc_ok ? (unsigned long)rtc.now().unixtime() : 0UL,
                  rtc_ok && rtc.lostPower() ? 1 : 0,
                  rtc_ok ? rtc.getTemperature() : 0.0f,
                  state_name(state));
}

static void handle_command(const char* cmd) {
    if (strcmp(cmd, "?") == 0) { report("NOW"); return; }

    if (cmd[0] == 'T' && cmd[1] == ' ') {
        // Digits only, nothing trailing. strtoul alone is not enough: it skips
        // whitespace and accepts a sign, and "-1" wraps to 4294967295 -- year
        // 2106, which an untrusted clock would otherwise accept.
        const char* digits = cmd + 2;
        char* end = nullptr;
        unsigned long epoch = (*digits >= '0' && *digits <= '9') ? strtoul(digits, &end, 10) : 0;
        if (end == nullptr || *end != '\0' || epoch > MAX_EPOCH || !apply_time((uint32_t)epoch)) {
            Serial.println("ERR rejected");
            return;
        }
        report("SET");
        return;
    }
    Serial.println("ERR unknown");
}

void clock_poll_serial() {
    static char   line[32];
    static size_t len = 0;
    static bool   overflow = false;

    while (Serial.available()) {
        char c = Serial.read();
        if (c == '\r') continue;
        if (c != '\n') {
            if (len < sizeof line - 1) line[len++] = c; else overflow = true;
            continue;
        }
        line[len] = '\0';
        // Drop over-long lines entirely rather than parsing a prefix.
        if (!overflow) handle_command(line);
        len = 0;
        overflow = false;
    }
}
