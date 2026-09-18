// Everything that touches the OLED. The panel object is private to this file
// so nothing else can draw behind its back.

#include "display.hpp"
#include "totp.hpp"

#include <Wire.h>
#include <string.h>

static Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

bool display_begin() {
    return display.begin(SSD1306_SWITCHCAPVCC, SCREEN_ADDR);
}

// Bottom-right "hamburger": four stacked lines when the code has just
// changed, then three, two, one as the 90 s window runs out. At one line the
// code is about to change -- wait for the next one rather than typing this
// one, so the screen says so.
static void draw_time_left(uint32_t seconds_left, uint32_t step_seconds) {
    if (seconds_left > step_seconds) seconds_left = step_seconds;
    int lines = (int)((seconds_left * 4 + step_seconds - 1) / step_seconds);   // ceil, 0..4
    if (lines < 1) lines = 1;

    const int w = 18, thick = 2, gap = 2;
    const int x = SCREEN_WIDTH - w;
    const int bottom = SCREEN_HEIGHT - 1;
    // Lines disappear from the top down, so the icon shrinks toward the
    // baseline like a stack being used up.
    for (int i = 0; i < lines; i++) {
        int y = bottom - thick + 1 - i * (thick + gap);
        display.fillRect(x, y, w, thick, SSD1306_WHITE);
    }
    if (lines == 1) {
        display.setTextSize(1);
        display.setCursor(x - 5 * 6 - 4, SCREEN_HEIGHT - 8);   // "wait" is 4 chars + space
        display.print("wait");
    }
}

void display_show_code(const char* code, const char* id, uint32_t seconds_left, uint32_t step_seconds) {
    // Two groups of four at text size 2: 9 characters x 12 px = 108 px of the
    // 128 px panel, centred, readable at arm's length while you type it.
    char grouped[10] = { code[0], code[1], code[2], code[3], ' ',
                         code[4], code[5], code[6], code[7], '\0' };

    display.clearDisplay();
    display.setTextColor(SSD1306_WHITE);
    display.setTextSize(2);
    display.setCursor((SCREEN_WIDTH - 9 * 12) / 2, 0);
    display.print(grouped);

    // Bottom row: ID on the left, time-left stack on the right.
    display.setTextSize(1);
    display.setCursor(0, SCREEN_HEIGHT - 8);
    display.print(id);
    draw_time_left(seconds_left, step_seconds);
    display.display();
}

void display_status(const char* text, const char* id) {
    display.clearDisplay();
    display.setTextColor(SSD1306_WHITE);
    display.setTextSize(2);
    int w = (int)strlen(text) * 12;
    display.setCursor(w < SCREEN_WIDTH ? (SCREEN_WIDTH - w) / 2 : 0, 0);
    display.print(text);
    display.setTextSize(1);
    display.setCursor(0, SCREEN_HEIGHT - 8);
    display.print(id);
    display.display();
}

void display_message(const char* text) {
    display.clearDisplay();
    display.setTextSize(1);
    display.setTextColor(SSD1306_WHITE);
    display.setCursor(0, 12);
    display.print(text);
    display.display();
}

void display_ln(){
  display.print("\n");
  display.display();
}

void demoBorder() {
  display.clearDisplay();
  // full-frame outline so you see the exact edges
  display.drawRect(0, 0, SCREEN_WIDTH, SCREEN_HEIGHT, SSD1306_WHITE);
  // corner pixels, dead center pixel
  display.drawPixel(0, 0, SSD1306_WHITE);
  display.drawPixel(SCREEN_WIDTH - 1, 0, SSD1306_WHITE);
  display.drawPixel(0, SCREEN_HEIGHT - 1, SSD1306_WHITE);
  display.drawPixel(SCREEN_WIDTH - 1, SCREEN_HEIGHT - 1, SSD1306_WHITE);
  display.setTextSize(1);
  display.setCursor(4, 12);
  display.print(SCREEN_WIDTH);
  display.print("x");
  display.print(SCREEN_HEIGHT);
  display.display();
}

void demoTextSize1() {
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  // 4 lines of 8px each fit exactly in 32px
  for (int line = 0; line < 4; line++) {
    display.setCursor(0, line * 8);
    display.print("Line ");
    display.print(line);
    display.print(" 12345678901234567890"); // long text to see wrap/cutoff
  }
  display.display();
}

void demoTextSize2() {
  display.clearDisplay();
  display.setTextSize(2);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 0);
  display.println("BIG1");
  display.setCursor(0, 16);
  display.println("BIG2");
  display.display();
}

void demoShapes() {
  display.clearDisplay();
  display.drawLine(0, 0, SCREEN_WIDTH - 1, SCREEN_HEIGHT - 1, SSD1306_WHITE);
  display.drawLine(0, SCREEN_HEIGHT - 1, SCREEN_WIDTH - 1, 0, SSD1306_WHITE);
  display.drawCircle(SCREEN_WIDTH / 2, SCREEN_HEIGHT / 2, 15, SSD1306_WHITE);
  display.fillRect(0, 0, 20, 20, SSD1306_WHITE);
  display.fillCircle(SCREEN_WIDTH - 10, SCREEN_HEIGHT - 10, 8, SSD1306_WHITE);
  display.display();
}

void demoInvert() {
  display.clearDisplay();
  display.fillRect(0, 0, SCREEN_WIDTH, SCREEN_HEIGHT, SSD1306_WHITE);
  display.setTextSize(2);
  display.setTextColor(SSD1306_BLACK);
  display.setCursor(10, 8);
  display.print("INVERT");
  display.display();
}

void demoRandomNoise() {
  display.clearDisplay();
  for (int i = 0; i < 300; i++) {
    display.drawPixel(random(SCREEN_WIDTH), random(SCREEN_HEIGHT), SSD1306_WHITE);
  }
  display.display();
}

void emin(){
  display.clearDisplay();
  display.setTextSize(2);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 0);
  display.println("olala");
  display.display();
}

void emin2(){
  display.clearDisplay();
  display.setTextSize(2);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 0);
  display.println("Jea");
  display.display();
}
