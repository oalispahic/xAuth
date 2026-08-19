"""Independent reference implementation of the xAuth OTP.

Deliberately written from the algorithm description, not ported from the C++,
so that agreement between the two means something. This is the cross-check
required by Phase 1 of docs/development-plan.md.

Key handling note: the HMAC key is the ASCII hex *characters* stored in the
keystore, not the bytes they decode to. The firmware does the same.
"""
import hmac, hashlib, struct, time

STEP = 90
DIGITS = 8


def code_for_counter(key: str, counter: int, digits: int = DIGITS) -> str:
    mac = hmac.new(key.encode(), struct.pack(">Q", counter), hashlib.sha256).digest()
    offset = mac[-1] & 0x0F
    binc = ((mac[offset] & 0x7F) << 24 | (mac[offset + 1] & 0xFF) << 16 |
            (mac[offset + 2] & 0xFF) << 8 | (mac[offset + 3] & 0xFF))
    return str(binc % (10 ** digits)).zfill(digits)


def code_now(key: str, now: float | None = None) -> str:
    return code_for_counter(key, int(now if now is not None else time.time()) // STEP)
