#pragma once

#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

// Panel geometry. One copy, so nothing can drift.
#define SCREEN_WIDTH  128
#define SCREEN_HEIGHT 32
#define OLED_RESET    -1
#define SCREEN_ADDR   0x3C

// Brings up the panel. Wire.begin() is NOT called here -- the I2C bus is
// shared with the DS3231, so the caller owns it.
bool display_begin();

// The normal screen: the 8-digit code in two groups of four, the device ID,
// and a four-line stack that loses a line per quarter of the 90-second
// window. One line left means: wait for the next code.
void display_show_code(const char* code, const char* id, uint32_t seconds_left, uint32_t step_seconds);

// A status screen for when there is no code to show (e.g. "SET TIME"), with
// the device ID underneath so the keychain can still be identified.
void display_status(const char* text, const char* id);

// Single line of status text.
void display_message(const char* text);

// Bench demos: wiring, I2C address and text metrics on a new panel. Nothing
// calls these in normal operation.
void demoBorder();
void demoTextSize1();
void demoTextSize2();
void demoShapes();
void demoInvert();
void demoRandomNoise();
void display_ln();
