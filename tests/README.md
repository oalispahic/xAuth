`otp_ref.py` is an independent Python implementation of the OTP, written from
the algorithm description rather than ported from the C++, so agreement between
them is meaningful evidence rather than a shared bug.

`vectors/otp-vectors.json` pins (key, counter) -> code with a fixed, non-secret
test key. Three implementations have to agree on these forever: core/otp.cpp,
otp_ref.py, and the BearSSL copy in firmware/xAuth_ID. Regenerate only if you
have deliberately changed the algorithm, and reflash every device if you do.
