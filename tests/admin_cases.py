"""Table-driven checks against a live admin daemon on a throwaway keystore.

    make test-admin
"""
from __future__ import annotations

import os, socket, sqlite3, subprocess, sys, tempfile, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ADMIN = os.path.join(ROOT, "build", "xauth-admin")
VERIFIER = os.path.join(ROOT, "build", "verifier")


def ask(sock_path: str, raw: bytes) -> str:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        s.connect(sock_path)
        s.sendall(raw)
        s.shutdown(socket.SHUT_WR)
        data = b""
        while True:
            chunk = s.recv(1024)
            if not chunk:
                break
            data += chunk
    return data.decode()


def wait_sock(p: str) -> bool:
    for _ in range(100):
        if os.path.exists(p):
            return True
        time.sleep(0.02)
    return False


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="xauth-admin-")
    db, sock, vsock = os.path.join(tmp, "auth"), os.path.join(tmp, "a.sock"), os.path.join(tmp, "v.sock")
    env = {"XAUTH_DB": db, "PATH": os.environ.get("PATH", "")}
    with open(os.path.join(ROOT, "db", "schema.sql")) as f:
        sqlite3.connect(db).executescript(f.read())

    admin = subprocess.Popen([ADMIN, "--socket", sock, "--allow-uid", str(os.getuid())], env=env, stderr=subprocess.DEVNULL)
    verifier = subprocess.Popen([VERIFIER, "--socket", vsock], env=env, stderr=subprocess.DEVNULL)
    failed = 0

    def check(name, ok, got=""):
        nonlocal failed
        failed += not ok
        print(f"  [{'PASS' if ok else 'FAIL'}] {name:44} {got}")

    try:
        if not (wait_sock(sock) and wait_sock(vsock)):
            print("daemons did not start")
            return 1

        check("empty LIST", ask(sock, b"LIST\n") == "END\n")

        r = ask(sock, b"ADD primary keychain\n").split()
        check("ADD returns OK <id> <key>", len(r) == 3 and r[0] == "OK" and len(r[1]) == 4 and len(r[2]) == 128, " ".join(r[:2]))
        dev, key = r[1], r[2]
        con = sqlite3.connect(db)
        row = con.execute("SELECT Key, Status, Note, Created FROM secure_key_data WHERE ID=?", (dev,)).fetchone()
        check("keystore row matches the reply", row is not None and row[0] == key and row[1] == 1 and row[2] == "primary keychain" and row[3])

        listing = ask(sock, b"LIST\n")
        check("LIST shows the device, never the key", f"DEVICE {dev} active " in listing and key not in listing and "primary keychain" in listing, listing.strip().replace("\n", " | "))
        check("LIST created field is one token", listing.split()[3].count("T") == 1 and " " not in listing.split()[3])

        check("verifier sees it active", ask(vsock, f"STATUS {dev}\n".encode()).strip() == "ACTIVE")
        check("REVOKE", ask(sock, f"REVOKE {dev}\n".encode()) == "OK\n")
        check("verifier sees the revocation at once", ask(vsock, f"STATUS {dev}\n".encode()).strip() == "INACTIVE")
        check("REVOKE unknown is NO", ask(sock, b"REVOKE ZZZZ\n") == "NO\n")
        check("ACTIVATE", ask(sock, f"ACTIVATE {dev}\n".encode()) == "OK\n")
        check("LABEL", ask(sock, f"LABEL {dev} spare, drawer\n".encode()) == "OK\n" and "spare, drawer" in ask(sock, b"LIST\n"))
        check("LABEL with a quote is ERR", ask(sock, f'LABEL {dev} a"b\n'.encode()) == "ERR\n")
        check("ADD with an empty label is ERR", ask(sock, b"ADD \n") == "ERR\n" and ask(sock, b"ADD\n") == "ERR\n")
        check("ADD with a 65-char label is ERR", ask(sock, b"ADD " + b"x" * 65 + b"\n") == "ERR\n")
        check("malformed ID is NO, not SQL", ask(sock, b"REVOKE ../x\n") == "NO\n")
        check("unknown command is ERR", ask(sock, b"DROP TABLE\n") == "ERR\n")
        check("over-long request is ERR", ask(sock, b"ADD " + b"a" * 300 + b"\n") == "ERR\n")
        check("EOF before newline is ERR", ask(sock, b"LIST") == "ERR\n")
        check("socket mode 0660", (os.stat(sock).st_mode & 0o777) == 0o660)

        # Six more devices: all IDs distinct.
        ids = [ask(sock, f"ADD d{i}\n".encode()).split()[1] for i in range(6)]
        check("IDs are unique", len(set(ids + [dev])) == 7)

        other = subprocess.Popen([ADMIN, "--socket", sock + "2", "--allow-uid", str(os.getuid() + 1)], env=env, stderr=subprocess.DEVNULL)
        try:
            wait_sock(sock + "2")
            try:
                got = ask(sock + "2", b"LIST\n")
            except OSError:
                got = ""
            check("disallowed uid refused", not got.startswith("DEVICE") and got != "END\n", repr(got))
        finally:
            other.terminate(); other.wait(5)

        print("\nALL PASS" if not failed else f"\n{failed} FAILED")
        return 1 if failed else 0
    finally:
        admin.terminate(); verifier.terminate()
        admin.wait(5); verifier.wait(5)


if __name__ == "__main__":
    sys.exit(main())
