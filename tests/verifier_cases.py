"""Table-driven checks against a live verifier daemon.

Builds a throwaway keystore, provisions devices with the real tool, starts
build/verifier on a temporary socket and drives it with every case from
docs/development-plan.md Phase 2: right code, wrong code, unknown device,
revoked device, adjacent windows, malformed input. Never touches db/auth.

    make test-verifier
"""
from __future__ import annotations

import os, socket, sqlite3, subprocess, sys, tempfile, time

sys.path.insert(0, os.path.dirname(__file__))
from otp_ref import code_for_counter, STEP  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VERIFIER = os.path.join(ROOT, "build", "verifier")
PROVISION = os.path.join(ROOT, "build", "provision")


def ask(sock_path: str, raw: bytes, timeout: float = 5.0) -> str:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(sock_path)
        s.sendall(raw)
        try:
            s.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        data = b""
        while True:
            chunk = s.recv(256)
            if not chunk:
                break
            data += chunk
    return data.decode()


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="xauth-verifier-")
    db = os.path.join(tmp, "auth")
    sock = os.path.join(tmp, "v.sock")
    env = {"XAUTH_DB": db, "PATH": os.environ.get("PATH", "")}

    with open(os.path.join(ROOT, "db", "schema.sql")) as f:
        sqlite3.connect(db).executescript(f.read())

    def provision(*args: str) -> str:
        return subprocess.run([PROVISION, *args], env=env, check=True,
                              capture_output=True, text=True).stdout.strip()

    active = provision("add", "--label", "active")
    revoked = provision("add", "--label", "revoked")
    provision("revoke", revoked)

    con = sqlite3.connect(db)
    key_of = lambda i: con.execute("SELECT Key FROM secure_key_data WHERE ID=?", (i,)).fetchone()[0]
    # Rows the provisioning tool would never write, to prove the verifier does
    # not trust the keystore's contents blindly.
    con.execute("INSERT INTO secure_key_data (ID, Key, Status) VALUES ('EMPT', '', 1)")
    con.execute("INSERT INTO secure_key_data (ID, Key, Status) VALUES ('SHRT', 'abc', 1)")
    con.commit()
    active_key, revoked_key = key_of(active), key_of(revoked)

    # --allow-uid as in production (deploy/docker-compose.yml), so the peer
    # check runs on every case -- and so the seccomp trace sees its syscalls.
    proc = subprocess.Popen([VERIFIER, "--socket", sock, "--allow-uid", str(os.getuid())], env=env,
                            stderr=subprocess.PIPE, text=True)
    try:
        for _ in range(100):
            if os.path.exists(sock):
                break
            time.sleep(0.02)
        else:
            print("verifier did not start:", proc.stderr.read() if proc.poll() is not None else "")
            return 1

        mode = os.stat(sock).st_mode & 0o777
        # Stay clear of a window boundary so -1/0/+1 mean what the cases say.
        if time.time() % STEP > STEP - 3:
            time.sleep(4)
        c = int(time.time()) // STEP

        V = lambda i, code: f"VERIFY {i} {code}\n".encode()
        cases = [
            ("right code, current window",        V(active, code_for_counter(active_key, c)),     f"OK {c}"),
            ("right code, previous window",       V(active, code_for_counter(active_key, c - 1)), f"OK {c - 1}"),
            ("right code, next window",           V(active, code_for_counter(active_key, c + 1)), f"OK {c + 1}"),
            ("code two windows old",              V(active, code_for_counter(active_key, c - 2)), "NO"),
            ("code two windows ahead",            V(active, code_for_counter(active_key, c + 2)), "NO"),
            ("wrong code",                        V(active, "00000000" if code_for_counter(active_key, c) != "00000000" else "11111111"), "NO"),
            ("unknown device",                    V("ZZZZ", code_for_counter(active_key, c)),     "NO"),
            ("revoked device, its own right code", V(revoked, code_for_counter(revoked_key, c)),  "NO"),
            ("empty key row, empty-key code",     V("EMPT", code_for_counter("", c)),              "NO"),
            ("short key row, short-key code",     V("SHRT", code_for_counter("abc", c)),           "NO"),
            ("path traversal ID",                 V("../../etc/passwd", "12345678"),              "NO"),
            ("lowercase ID",                      V(active.lower(), code_for_counter(active_key, c)), "NO"),
            ("ID with ambiguous letter",          V("ABCI", "12345678"),                          "NO"),
            ("ID too short",                      V("ABC", "12345678"),                           "NO"),
            ("ID too long",                       V("ABCDEFGHJ", "12345678"),                     "NO"),
            ("SQL-shaped ID",                     V("A'OR1", "12345678"),                         "NO"),
            ("7-digit code",                      V(active, "1234567"),                           "NO"),
            ("9-digit code",                      V(active, "123456789"),                         "NO"),
            ("non-digit code",                    V(active, "1234567a"),                          "NO"),
            ("extra field",                       f"VERIFY {active} 12345678 x\n".encode(),       "ERR"),
            ("unknown command",                   b"HELLO\n",                                     "ERR"),
            ("over-long request",                 b"VERIFY " + b"A" * 200 + b"\n",                "ERR"),
            ("EOF before newline",                f"VERIFY {active} 12345678".encode(),           "ERR"),
            ("empty request",                     b"",                                            "ERR"),
            ("STATUS active",                     f"STATUS {active}\n".encode(),                  "ACTIVE"),
            ("STATUS revoked",                    f"STATUS {revoked}\n".encode(),                 "INACTIVE"),
            ("STATUS unknown",                    b"STATUS ZZZZ\n",                               "INACTIVE"),
            ("STATUS malformed",                  b"STATUS ../x\n",                               "INACTIVE"),
        ]

        failed = 0
        for name, raw, want in cases:
            got = ask(sock, raw).strip()
            ok = got == want
            failed += not ok
            print(f"  [{'PASS' if ok else 'FAIL'}] {name:38} want={want!r:10} got={got!r}")

        # Revocation takes effect on the next lookup, with no restart.
        provision("revoke", active)
        got = ask(sock, V(active, code_for_counter(active_key, c))).strip()
        ok = got == "NO"
        failed += not ok
        print(f"  [{'PASS' if ok else 'FAIL'}] {'revoked while running':38} want='NO'       got={got!r}")
        provision("activate", active)

        ok = mode == 0o660
        failed += not ok
        print(f"  [{'PASS' if ok else 'FAIL'}] {'socket mode 0660':38} got={oct(mode)}")

        # A second daemon that only accepts some other uid must refuse us,
        # even with a right code.
        sock2 = os.path.join(tmp, "v2.sock")
        other = subprocess.Popen([VERIFIER, "--socket", sock2, "--allow-uid", str(os.getuid() + 1)],
                                 env=env, stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                if os.path.exists(sock2):
                    break
                time.sleep(0.02)
            try:
                got = ask(sock2, V(active, code_for_counter(active_key, int(time.time()) // STEP))).strip()
            except OSError:
                got = ""
            ok = not got.startswith("OK")
            failed += not ok
            print(f"  [{'PASS' if ok else 'FAIL'}] {'disallowed uid refused':38} got={got!r}")
        finally:
            other.terminate()
            other.wait(timeout=5)

        print("\nALL PASS" if not failed else f"\n{failed} FAILED")
        return 1 if failed else 0
    finally:
        proc.terminate()
        proc.wait(timeout=5)


if __name__ == "__main__":
    sys.exit(main())
