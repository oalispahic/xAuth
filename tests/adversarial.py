"""Adversarial suite for xAuth. Re-run after ANY change to verifier/, core/,
auth-web/ or nginx/.

    make adversarial            # or: python3 tests/adversarial.py

Starts its own verifier daemon (on a throwaway keystore -- db/auth is never
touched) and its own auth-web, then attacks them:

  verifier   timing: unknown ID vs known ID with a wrong code
  admin      non-admins and tokens kept out, CSRF, create/revoke round trip
  auth-web   brute force, IP budget, replay (sequential and concurrent),
             malformed and path-traversal IDs, cookie tampering, token
             tampering, CSRF, open redirects, header injection, oversize
             bodies, revocation of a live session and a live token
  nginx      if the dev harness is up (docker compose -f dev/docker-compose.yml
             up -d): deep-link round trip, token through the gate, token
             stripped before the app, /_xauth/verify unreachable from outside

auth-web listens on 127.0.0.1:3100, where the harness nginx expects it, so
stop `npm run dev` first. Uses Redis from dev/xauth.env when reachable,
in-memory stores otherwise.

    python3 tests/adversarial.py --stack

attacks the hardened containers from deploy/docker-compose.yml instead, already
running with a throwaway keystore -- see deploy/README.md. The verifier timing
check is skipped there: the daemon's socket lives inside a Docker volume.
"""
from __future__ import annotations

import concurrent.futures, http.client, os, re, socket, sqlite3, statistics
import subprocess, sys, tempfile, time, urllib.parse

sys.path.insert(0, os.path.dirname(__file__))
from otp_ref import code_for_counter, STEP  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD = os.path.join(ROOT, "build")
AUTH_ORIGIN = "http://auth.xauth.test:8080"
APP = "http://app.xauth.test:8080"
PORT = 3100

failures: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}{f'  ({detail})' if detail else ''}")
    if not ok:
        failures.append(name)


def section(title: str) -> None:
    print(f"\n{title}")


# ---- plumbing ----------------------------------------------------------------

class Resp:
    def __init__(self, status, headers, body):
        self.status, self.headers, self.body = status, headers, body

    def header(self, name):
        for k, v in self.headers:
            if k.lower() == name.lower():
                return v
        return None

    def cookies(self):
        return [v for k, v in self.headers if k.lower() == "set-cookie"]


def req(method, path, *, host="127.0.0.1", port=PORT, headers=None, body=None, host_header=None):
    conn = http.client.HTTPConnection(host, port, timeout=10)
    h = dict(headers or {})
    if host_header:
        h["Host"] = host_header
    if isinstance(body, dict):
        body = urllib.parse.urlencode(body)
        h.setdefault("Content-Type", "application/x-www-form-urlencoded")
    conn.request(method, path, body=body, headers=h)
    r = conn.getresponse()
    out = Resp(r.status, r.getheaders(), r.read().decode(errors="replace"))
    conn.close()
    return out


_ip = [0]


def fresh_ip() -> str:
    """A distinct client address per call, so per-IP budgets don't mask the
    per-device budget being tested. auth-web trusts X-Forwarded-For from
    loopback, exactly as it does behind nginx."""
    _ip[0] += 1
    return f"198.51.100.{_ip[0] % 250 + 1}" if _ip[0] < 250 else f"203.0.113.{_ip[0] % 250 + 1}"


def login(device, code, *, redirect=None, origin=AUTH_ORIGIN, ip=None):
    form = {"device_id": device, "code": code}
    if redirect:
        form["redirect"] = redirect
    headers = {"X-Forwarded-For": ip or fresh_ip()}
    if origin:
        headers["Origin"] = origin
    return req("POST", "/otp", headers=headers, body=form)


def session_of(resp) -> str | None:
    for c in resp.cookies():
        if c.startswith("xauth_session=") and not c.startswith("xauth_session=;"):
            return c.split(";")[0]
    return None


def verify(cookie=None, token=None):
    h = {}
    if cookie:
        h["Cookie"] = cookie
    if token:
        h["X-xAuth-Token"] = token
    return req("GET", "/verify", headers=h).status


def ask_socket(path: str, line: str) -> str:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(path)
        s.sendall(line.encode())
        return s.recv(64).decode().strip()


def wait_for(predicate, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def port_open(port, host="127.0.0.1"):
    try:
        socket.create_connection((host, port), timeout=0.3).close()
        return True
    except OSError:
        return False


def fresh_window(min_left=25):
    """Waits until at least `min_left` seconds remain in the OTP window, so a
    test that must stay inside one window can."""
    left = STEP - time.time() % STEP
    if left < min_left:
        time.sleep(left + 0.5)


# ---- the suite -----------------------------------------------------------------

def main() -> int:
    stack = "--stack" in sys.argv[1:]
    if stack:
        return run(stack=True)
    if port_open(PORT):
        print(f"Something is already listening on {PORT}. Stop `npm run dev` first.")
        return 2
    return run(stack=False)


def run(stack: bool) -> int:
    for tool in ("verifier", "provision"):
        if not os.path.exists(os.path.join(BUILD, tool)):
            print("Run `make` first.")
            return 2

    tmp = tempfile.mkdtemp(prefix="xauth-adv-")
    sock = os.path.join(tmp, "v.sock")
    asock = os.path.join(tmp, "a.sock")
    env_db = {"PATH": os.environ.get("PATH", "")}
    if stack:
        db = os.path.join(os.environ["XAUTH_KEYSTORE_DIR"], "auth")
        compose = ["docker", "compose", "-f", os.path.join(ROOT, "deploy", "docker-compose.yml"),
                   "run", "--rm", "-T", "provision"]

        def provision(*args):
            return subprocess.run([*compose, *args], check=True, capture_output=True,
                                  text=True).stdout.strip().splitlines()[-1]
    else:
        db = os.path.join(tmp, "auth")
        with open(os.path.join(ROOT, "db", "schema.sql")) as f:
            sqlite3.connect(db).executescript(f.read())
        env_db["XAUTH_DB"] = db

        def provision(*args):
            return subprocess.run([os.path.join(BUILD, "provision"), *args], env=env_db,
                                  check=True, capture_output=True, text=True).stdout.strip()

    devices = [provision("add", "--label", f"adv{i}") for i in range(7)]
    con = sqlite3.connect(db)
    keys = {d: con.execute("SELECT Key FROM secure_key_data WHERE ID=?", (d,)).fetchone()[0] for d in devices}
    code_now = lambda d, off=0: code_for_counter(keys[d], int(time.time()) // STEP + off)
    # One device per test: the budget is 2 attempts per device per window, so
    # sharing a device would let one test pass on another's spent budget.
    brute, replay, race, older, revokee, spare, adm = devices
    web_env_admin = {"ADMIN_DEVICES": adm}

    use_redis = stack or port_open(6379)
    web_env = {
        "PATH": os.environ.get("PATH", ""),
        "HOST": "127.0.0.1", "PORT": str(PORT),
        "AUTH_ORIGIN": AUTH_ORIGIN, "ALLOWED_HOSTS": "app.xauth.test:8080",
        "ALLOW_HTTP_REDIRECTS": "true", "COOKIE_DOMAIN": "xauth.test", "COOKIE_SECURE": "false",
        "VERIFIER_SOCKET": sock, "ADMIN_SOCKET": asock, "ADMIN_DEVICES": "",
        "STATUS_CACHE_SECONDS": "1", "IP_ATTEMPTS_PER_MINUTE": "20",
        **({"REDIS_URL": "redis://127.0.0.1:6379"} if use_redis else {}),
        **web_env_admin,
    }
    procs = []
    if not stack:
        procs.append(subprocess.Popen([os.path.join(BUILD, "verifier"), "--socket", sock], env=env_db,
                                      stderr=subprocess.DEVNULL))
        procs.append(subprocess.Popen([os.path.join(BUILD, "xauth-admin"), "--socket", asock], env=env_db,
                                      stderr=subprocess.DEVNULL))
        procs.append(subprocess.Popen(["node", "src/server.js"], cwd=os.path.join(ROOT, "auth-web"),
                                      env=web_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    try:
        if not stack and not wait_for(lambda: os.path.exists(sock)):
            print("verifier did not start")
            return 1
        if not wait_for(lambda: port_open(PORT)):
            print("auth-web is not listening on", PORT)
            return 1
        print(f"target: {'hardened stack' if stack else 'local processes'}   "
              f"store: {'redis' if use_redis else 'memory'}   devices: {', '.join(devices)}")

        # -- 1. timing -------------------------------------------------------------
        section("Timing (verifier socket, unknown ID vs known ID + wrong code)")
        known, unknown = [], []
        if stack:
            print("  [SKIP] socket is inside the stack's volume; same binary as the local run")
        for i in range(0 if stack else 6000):
            which = i % 2
            line = f"VERIFY {spare if which else 'ZZZZ'} 00000001\n"
            t = time.perf_counter_ns()
            ask_socket(sock, line)
            (known if which else unknown).append(time.perf_counter_ns() - t)
        if not stack:
            mk, mu = statistics.median(known), statistics.median(unknown)
            diff = abs(mk - mu) / min(mk, mu)
            check("no visible timing difference", diff < 0.10,
                  f"known {mk / 1000:.1f}us, unknown {mu / 1000:.1f}us, diff {diff:.1%}")

        # -- 2. brute force --------------------------------------------------------
        section("Brute force")
        fresh_window()
        wrong = "00000000" if code_now(brute) != "00000000" else "11111111"
        for _ in range(30):
            login(brute, wrong)
        r = login(brute, code_now(brute))
        check("device budget holds after 30 wrong codes, right code refused", session_of(r) is None)
        r = [login(brute, wrong, ip="192.0.2.77") for _ in range(25)]
        check("per-IP budget answers identically when exhausted",
              len({x.header("location") for x in r}) == 1 and all(x.status == 303 for x in r))

        # -- 3. malformed input ----------------------------------------------------
        section("Malformed input")
        locations = set()
        for dev, code in [("../../etc/passwd", "12345678"), ("A'OR'1'='1", "12345678"),
                          ("%2e%2e%2f", "12345678"), ("ABCD\r\nX: y", "12345678"),
                          ("A" * 500, "12345678"), (brute, "1" * 500), ("", ""),
                          ("ZZZZ", code_now(brute)), (spare, "abcdefgh")]:
            r = login(dev, code)
            locations.add(r.header("location"))
            if session_of(r):
                check(f"malformed {dev[:20]!r} rejected", False)
        check("every malformed or unknown input gets the same response", len(locations) == 1, str(locations))
        r = req("POST", "/otp", headers={"Origin": AUTH_ORIGIN}, body={"device_id": "A" * 5000, "code": "1"})
        check("oversize body refused", r.status == 413 and not session_of(r), str(r.status))

        # -- 4. replay ---------------------------------------------------------------
        section("Replay")
        fresh_window()
        code = code_now(replay)
        first = session_of(login(replay, code))
        second = session_of(login(replay, code))
        check("a code logs in once, sequentially", first is not None and second is None)
        # Concurrent: one right code raced 8 ways. Two fit in the budget; the
        # claim must still let exactly one of them through.
        rc = code_now(race)
        with concurrent.futures.ThreadPoolExecutor(8) as ex:
            wins = [session_of(r) for r in ex.map(lambda _: login(race, rc), range(8))]
        wins = [w for w in wins if w]
        check("a code logs in exactly once under 8 concurrent attempts", len(wins) == 1, f"{len(wins)} sessions")
        # The verifier accepts the next window's code; once that is used, the
        # current window's code is older and must be refused.
        newer = session_of(login(older, code_now(older, 1)))
        stale = session_of(login(older, code_now(older)))
        check("an older code is refused after a newer one", newer is not None and stale is None)

        # -- 5. cookies and tokens -----------------------------------------------------
        section("Cookie and token tampering")
        cookie = first
        check("valid session passes /verify", verify(cookie=cookie) == 200)
        name, value = cookie.split("=", 1)
        tampered = [value[:-1] + ("A" if value[-1] != "A" else "B"), value[1:], value + "A", "", "A" * 400,
                    value.upper(), "' OR 1=1 --"]
        check("every tampered cookie is refused", all(verify(cookie=f"{name}={v}") == 401 for v in tampered))

        page = req("POST", "/tokens", headers={"Origin": AUTH_ORIGIN, "Cookie": cookie}, body={"label": "adv"})
        m = re.search(r'value="(xat_[A-Za-z0-9_-]{43})"', page.body)
        token = m.group(1) if m else None
        check("device token issued", token is not None)
        if token:
            check("token passes /verify", verify(token=token) == 200)
            bad = [token[:-1] + ("A" if token[-1] != "A" else "B"), token[:-1], token + "A", "xat_" + "A" * 43]
            check("every tampered token is refused", all(verify(token=t) == 401 for t in bad))
            check("token in Authorization is refused",
                  req("GET", "/verify", headers={"Authorization": f"Bearer {token}"}).status == 401)
            check("token in query string is refused", req("GET", f"/verify?token={token}").status == 401)
            r = req("POST", "/tokens", headers={"Origin": AUTH_ORIGIN, "X-xAuth-Token": token}, body={"label": "x"})
            check("a token cannot mint tokens", r.status == 303 and "xat_" not in r.body)

        # -- 6. CSRF and redirects -------------------------------------------------------
        section("CSRF and redirects")
        for origin in (None, "https://evil.example", "null", APP):
            r = login(replay, "12345678", origin=origin)
            check(f"login POST with Origin={origin} refused", r.status == 403)
        for origin in (None, "https://evil.example"):
            h = {"Cookie": cookie, **({"Origin": origin} if origin else {})}
            check(f"token POST with Origin={origin} refused",
                  req("POST", "/tokens", headers=h, body={"label": "x"}).status == 403)
            check(f"logout with Origin={origin} refused", req("POST", "/logout", headers=h).status == 403)
        evil = ["https://evil.example/", "//evil.example/", "/\\evil.example", "http://app.xauth.test:8080@evil.example/",
                "http://app.xauth.test:8080.evil.example/", "javascript:alert(1)", "http://app.xauth.test:8081/", "data:text/html,x", APP + "/" + "a" * 3000]
        for target in evil:
            r = req("GET", "/start", headers={"X-Original-URL": target})
            loc = r.header("location") or ""
            q = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query).get("redirect", [""])[0]
            if q and not q.startswith(APP + "/"):
                check(f"/start refuses {target[:40]!r}", False, loc)
            r = req("GET", "/login?redirect=" + urllib.parse.quote(target, safe=""))
            if "evil.example" in r.body:
                check(f"login page refuses {target[:40]!r}", False)
        check("no redirect bypass among " + str(len(evil)) + " targets", True)
        r = req("GET", "/start", headers={"X-Original-URL": APP + "/a%0d%0aSet-Cookie:%20x=1"})
        check("CRLF in the original URL is not a header", not any(c.startswith("x=1") for c in r.cookies()))
        r = login(replay, "00000000", redirect="https://evil.example/")
        check("failed login does not echo a foreign redirect", "evil.example" not in (r.header("location") or ""))

        # -- 7. revocation --------------------------------------------------------------
        section("Revocation")
        fresh_window()
        live = session_of(login(revokee, code_now(revokee)))
        page = req("POST", "/tokens", headers={"Origin": AUTH_ORIGIN, "Cookie": live}, body={"label": "r"})
        rtoken = (re.search(r'value="(xat_[^"]+)"', page.body) or [None, None])[1]
        check("session and token work before revocation", verify(cookie=live) == 200 and verify(token=rtoken) == 200)
        provision("revoke", revokee)
        time.sleep(1.2)   # STATUS_CACHE_SECONDS=1
        check("revoked device: live session refused", verify(cookie=live) == 401)
        check("revoked device: live token refused", verify(token=rtoken) == 401)
        fresh_window()
        check("revoked device: its right code is refused", session_of(login(revokee, code_now(revokee))) is None)

        # -- 8. admin dashboard ------------------------------------------------------------
        section("Admin dashboard")
        if stack:
            print("  [SKIP] ADMIN_DEVICES is fixed by the stack's env file")
        else:
            non_admin = cookie   # `replay` device's session from above
            check("non-admin session gets 404, not the page", req("GET", "/admin", headers={"Cookie": non_admin}).status == 404)
            check("no session is sent to login", req("GET", "/admin").status == 303)
            r = req("POST", "/admin/devices", headers={"Cookie": non_admin, "Origin": AUTH_ORIGIN}, body={"label": "x"})
            check("non-admin cannot create devices", r.status == 404)
            fresh_window()
            acookie = session_of(login(adm, code_now(adm)))
            check("admin session sees the dashboard", acookie is not None and req("GET", "/admin", headers={"Cookie": acookie}).status == 200)
            if token:
                check("token cannot reach /admin", req("GET", "/admin", headers={"X-xAuth-Token": token}).status == 303)
            for origin in (None, "https://evil.example"):
                h = {"Cookie": acookie, **({"Origin": origin} if origin else {})}
                check(f"admin POST with Origin={origin} refused",
                      req("POST", "/admin/devices/revoke", headers=h, body={"id": spare}).status == 403)
            r = req("POST", "/admin/devices", headers={"Cookie": acookie, "Origin": AUTH_ORIGIN}, body={"label": "from dashboard"})
            m = re.search(r"#define DEVICE_ID  &quot;([0-9A-Z]{4})&quot;", r.body)
            check("admin creates a device and sees the header once", r.status == 200 and m is not None)
            if m:
                newdev = m.group(1)
                again = req("GET", "/admin", headers={"Cookie": acookie}).body
                check("key is not shown again", "SECURE_KEY" not in again and newdev in again)
                r = req("POST", "/admin/devices/revoke", headers={"Cookie": acookie, "Origin": AUTH_ORIGIN}, body={"id": newdev})
                check("admin revokes it", r.status == 200 and ask_socket(sock, f"STATUS {newdev}\n") == "INACTIVE")
            r = req("POST", "/admin/devices/revoke", headers={"Cookie": acookie, "Origin": AUTH_ORIGIN}, body={"id": adm})
            check("last admin cannot revoke itself", r.status == 409)
            r = req("POST", "/admin/devices", headers={"Cookie": acookie, "Origin": AUTH_ORIGIN}, body={"label": 'a"; DROP TABLE x; --'})
            check("hostile label refused", r.status == 400)

        # -- 9. through nginx -------------------------------------------------------------
        section("Through the nginx gate (dev harness)")
        if not port_open(8080):
            print("  [SKIP] harness not running: docker compose -f dev/docker-compose.yml up -d")
        else:
            g = lambda path, **kw: req("GET", path, port=8080, host_header="app.xauth.test:8080", **kw)
            target = "/photos/2026?album=summer&sort=desc"
            r = g(target)
            loc = r.header("location") or ""
            red = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query).get("redirect", [""])[0]
            check("unauthenticated deep link redirects to login", r.status == 302 and loc.startswith(AUTH_ORIGIN + "/login"))
            check("deep link survives encoding intact", red == APP + target, red)
            check("app content never shown without a session", "Mock app" not in r.body)
            r = g(target, headers={"Cookie": cookie})
            check("session opens the gate", r.status == 200)
            check("gated responses must be revalidated (no cached page after sign-out)",
                  (r.header("cache-control") or "") == "private, no-cache", r.header("cache-control") or "none")
            if token:
                check("token opens the gate", g("/api/x", headers={"X-xAuth-Token": token}).status == 200)
                echo = g("/_echo/token", headers={"X-xAuth-Token": token}).body.strip()
                check("token is stripped before reaching the app", echo == "token=[]", echo)
            check("health bypass stays open", g("/health").status == 200)
            check("/_xauth/verify is not reachable from outside", g("/_xauth/verify").status in (302, 404))
            check("unknown hosts are dropped",
                  _dropped(lambda: req("GET", "/", port=8080, host_header="evil.example")))
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            p.wait(5)

    print("\nALL PASS" if not failures else f"\n{len(failures)} FAILED:\n  " + "\n  ".join(failures))
    return 1 if failures else 0


def _dropped(fn) -> bool:
    try:
        fn()
        return False
    except (http.client.RemoteDisconnected, ConnectionResetError):
        return True


if __name__ == "__main__":
    sys.exit(main())
