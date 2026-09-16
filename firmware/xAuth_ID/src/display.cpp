// Everything that touches the OLED. The panel object is private to this file
// so nothing else can draw behind its back.

#include "display.hpp"
#include "totp.hpp"

#include <Wire.h>

static Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

bool display_begin() {
    return display.begin(SSD1306_SWITCHCAPVCC, SCREEN_ADDR);
}

void display_show_code(const char* code) {
    // Split into two groups of four. Eight digits at text size 2 is 96 px of a
    // 128 px panel, so the space fits and the code stays readable at arm's
    // length while you type it.
    char left[5]  = { code[0], code[1], code[2], code[3], '\0' };
    char right[5] = { code[4], code[5], code[6], code[7], '\0' };

    display.clearDisplay();
    display.setTextSize(1);
    display.setTextColor(SSD1306_WHITE);
    display.setCursor(0, 8);
    display.print(left);
    display.print(" ");
    display.print(right);
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
