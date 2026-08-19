"""Assert core/otp.cpp and otp_ref.py both reproduce the golden vectors.

If this fails, the OTP algorithm changed. Every device already in the field
stops working the moment that happens -- treat a failure here as a breaking
change, not a broken test.
"""
import json, subprocess, sys, pathlib

root = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root / "tests"))
from otp_ref import code_for_counter

spec = json.loads((root / "tests/vectors/otp-vectors.json").read_text())
key, vectors = spec["key"], spec["vectors"]
counters = [str(v["counter"]) for v in vectors]

cpp = subprocess.run([str(root / "build/otpgen"), key, *counters],
                     capture_output=True, text=True, check=True).stdout.split()

fail = 0
for vec, got_cpp in zip(vectors, cpp):
    got_py, want = code_for_counter(key, vec["counter"]), vec["code"]
    ok = got_cpp == want == got_py
    fail += not ok
    print(f"  [{'PASS' if ok else 'FAIL'}] counter={vec['counter']:<10} "
          f"golden={want} cpp={got_cpp} py={got_py}")

print("\nALL PASS" if not fail else f"\n{fail} MISMATCH(ES)")
sys.exit(1 if fail else 0)
