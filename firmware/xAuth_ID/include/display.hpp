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

// Shows an 8-digit code split into two groups, the way it is read aloud.
void display_show_code(const char* code);

// Single line of status text, for states where there is no code to show.
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
