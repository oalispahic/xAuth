| File | What it proves | Run |
|---|---|---|
| `check_vectors.py` + `otp_ref.py` | The C++ OTP agrees with an independent Python implementation on golden vectors. | `make test` |
| `verifier_cases.py` | The verifier daemon answers every case correctly: windows, unknown/revoked/malformed devices, bad keystore rows, oversize and truncated requests, peer uid. | `make test-verifier` |
| `adversarial.py` | Attacks a live verifier + auth-web (and nginx, if the dev harness is up): timing, brute force, replay, tampering, CSRF, redirects, revocation. `--stack` targets the hardened containers. | `make adversarial` |

`otp_ref.py` is written from the algorithm description rather than ported from
the C++, so agreement between them is meaningful evidence rather than a shared
bug.

`vectors/otp-vectors.json` pins (key, counter) -> code with a fixed, non-secret
test key. Three implementations have to agree on these forever: core/otp.cpp,
otp_ref.py, and the mbedTLS copy in firmware/xAuth_ID. Regenerate only if you
have deliberately changed the algorithm, and reflash every device if you do.

None of these touch `db/auth`. Each builds its own throwaway keystore.
