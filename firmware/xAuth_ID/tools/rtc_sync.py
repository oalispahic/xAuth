#!/usr/bin/env python3
"""Check or set the keychain's DS3231 over USB serial.

    rtc_sync.py check [PORT]
    rtc_sync.py set   [PORT]

Your computer's clock is the reference, so make sure it is synced first
(Linux: `timedatectl` says "System clock synchronized: yes"; macOS:
`sntp time.apple.com`). Close the serial monitor: only one program can hold
the port.

A device whose clock is already trusted only accepts corrections of up to
five minutes. Anything bigger is refused -- by design, so nobody can move the
clock forward to read future codes.
"""
import sys
import time

import serial
from serial.tools import list_ports

ESPRESSIF_VID = 0x303A   # ESP32-C3 native USB, same on every OS


def find_port():
    ports = [p.device for p in list_ports.comports() if p.vid == ESPRESSIF_VID]
    if len(ports) != 1:
        sys.exit(f"expected one ESP32-C3, found {ports or 'none'}; pass the port explicitly")
    return ports[0]


def open_port(dev):
    s = serial.Serial()
    s.port, s.baudrate, s.timeout = dev, 115200, 0.5
    s.dtr = s.rts = False   # set before open, or opening the port can reset the board
    s.open()
    return s


def ask(s, line, attempts=5):
    for _ in range(attempts):
        s.reset_input_buffer()
        s.write(line.encode() + b"\n")
        deadline = time.time() + 2
        while time.time() < deadline:
            reply = s.readline().decode(errors="replace").strip()
            if reply.startswith(("NOW", "SET", "ERR")):
                return reply
    sys.exit("no reply -- is the firmware running, and is the serial monitor closed?")


def show(label, reply):
    if reply.startswith("ERR"):
        sys.exit(f"{label}: {reply}")
    fields = dict(f.split("=", 1) for f in reply.split()[1:])
    t = int(fields["t"])
    print(f"{label:7} {reply}   device - host = {t - int(time.time()):+d} s")
    return fields


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "check"
    if mode not in ("check", "set"):
        sys.exit(__doc__)
    s = open_port(sys.argv[2] if len(sys.argv) > 2 else find_port())

    before = show("before", ask(s, "?"))   # also proves the firmware is up
    if before.get("state") == "no_rtc":
        sys.exit("the DS3231 is not on the I2C bus -- check wiring (expect 0x68)")

    if mode == "set":
        # Send exactly on a whole-second boundary. Writing the DS3231's seconds
        # register restarts its internal divider, so the new second begins
        # within a few ms of the host's. Sent once only: a retry could deliver
        # a stale time.
        time.sleep(1 - time.time() % 1)
        show("after", ask(s, f"T {round(time.time())}", attempts=1))


if __name__ == "__main__":
    main()
