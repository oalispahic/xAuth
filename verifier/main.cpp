// xAuth verifier daemon.
//
// The only process that ever holds key material. It listens on a Unix domain
// socket and answers one question per connection:
//
//   VERIFY <device-id> <code>\n   ->  OK <counter>\n   or   NO\n
//   STATUS <device-id>\n          ->  ACTIVE\n         or   INACTIVE\n
//   anything else                 ->  ERR\n
//
// OK carries the counter the code matched, so the caller can claim exactly
// that window against replay. The counter is derived from the clock, not from
// the key, so it tells the caller nothing it could not compute itself.
//
// STATUS lets auth-web kill live sessions of a revoked device without ever
// reading the keystore. It is only asked about IDs that already hold a
// session, never about IDs typed into the login form.
//
//   usage: verifier --socket PATH [--mode 0660] [--allow-uid UID]
//
// The keystore path comes from $XAUTH_DB (see core/keystore.hpp).

#include "../core/otp.hpp"
#include "../core/keystore.hpp"

#include <openssl/crypto.h>   // CRYPTO_memcmp, OPENSSL_cleanse
#include <openssl/rand.h>

#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <csignal>
#include <cerrno>
#include <cstring>

#ifdef __linux__
#include <sys/prctl.h>
#endif

#include <atomic>
#include <iostream>
#include <string>
#include <thread>

namespace {

constexpr size_t MAX_REQUEST = 64;      // "VERIFY " + 8 + " " + 8 + "\n" is 26
constexpr int    IO_TIMEOUT_SEC = 2;
constexpr int    MAX_IN_FLIGHT = 32;
constexpr int    KEY_HEX_LEN = 128;     // what tools/provision writes

std::atomic<int> in_flight{0};

// Held for the life of the process. Unknown and revoked IDs are verified
// against this, so they cost the same work as a real device and no timing
// difference says which IDs exist (architecture.md section 6). It is random
// per process, so no code ever matches it in a way anyone could predict --
// and a match is ignored anyway, because `real` is false.
std::string dummy_key;

char socket_path[sizeof(sockaddr_un::sun_path)];

void on_signal(int) {
    // unlink and _exit are async-signal-safe.
    unlink(socket_path);
    _exit(0);
}

bool all_digits(const std::string& s) {
    for (char c : s) {
        if (c < '0' || c > '9') return false;
    }
    return true;
}

std::string random_hex_key() {
    unsigned char buf[KEY_HEX_LEN / 2];
    if (RAND_bytes(buf, sizeof buf) != 1) {
        std::cerr << "verifier: RAND_bytes failed" << std::endl;
        std::exit(1);
    }
    static const char hex[] = "0123456789abcdef";
    std::string key;
    key.reserve(KEY_HEX_LEN);
    for (unsigned char b : buf) {
        key += hex[b >> 4];
        key += hex[b & 0x0F];
    }
    OPENSSL_cleanse(buf, sizeof buf);
    return key;
}

// Checks `code` against counter-1, counter and counter+1, always all three,
// always with a key -- the device's if it is real and active, the dummy one
// otherwise. Returns the matched counter via `matched`.
bool verify_code(const std::string& id, const std::string& code, uint64_t& matched) {
    bool code_ok = code.size() == OTP_SIZE && all_digits(code);

    Device device;
    Lookup found = find_device(id, device);   // malformed IDs are NotFound, no SQL
    if (found == Lookup::Error) {
        // Operator-only. Never changes what the caller sees.
        std::cerr << "verifier: keystore lookup failed" << std::endl;
    }

    // Fail closed. find_device() only writes on a hit and Device defaults to
    // revoked, but check everything anyway: an empty or short key is not a
    // secret, and HMAC'ing with one would let anyone compute the "valid" code.
    bool real = found == Lookup::Found && device.status == 1 &&
                device.key.size() == static_cast<size_t>(KEY_HEX_LEN);
    const std::string& key = real ? device.key : dummy_key;

    // A malformed code is still compared, against a placeholder of the right
    // length, so the work done does not depend on the input's shape.
    const std::string submitted = code_ok ? code : std::string(OTP_SIZE, 'x');

    uint64_t now = counter_for_time(time(nullptr));
    bool any = false;
    matched = 0;
    for (int offset = -1; offset <= 1; offset++) {
        uint64_t counter = now + offset;
        std::string expected = pad_and_convert(totp_for_counter(key, counter));
        // Constant-time: an early-exit compare leaks how many leading digits
        // were right. Lengths are both OTP_SIZE and public.
        bool eq = expected.size() == submitted.size() &&
                  CRYPTO_memcmp(expected.data(), submitted.data(), expected.size()) == 0;
        OPENSSL_cleanse(&expected[0], expected.size());
        if (eq && !any) {
            any = true;
            matched = counter;
        }
    }

    if (!device.key.empty()) OPENSSL_cleanse(&device.key[0], device.key.size());
    return real && code_ok && any;
}

std::string handle_request(const std::string& line) {
    // Split on single spaces. Anything that is not exactly the expected shape
    // is ERR -- no trimming, no case folding; auth-web normalizes before sending.
    std::string parts[4];
    int n = 0;
    size_t start = 0;
    while (n < 4) {
        size_t sp = line.find(' ', start);
        parts[n++] = line.substr(start, sp == std::string::npos ? std::string::npos : sp - start);
        if (sp == std::string::npos) break;
        start = sp + 1;
    }

    if (n == 3 && parts[0] == "VERIFY") {
        uint64_t matched = 0;
        bool ok = verify_code(parts[1], parts[2], matched);
        OPENSSL_cleanse(&parts[2][0], parts[2].size());
        return ok ? "OK " + std::to_string(matched) + "\n" : "NO\n";
    }
    if (n == 2 && parts[0] == "STATUS") {
        Device device;
        Lookup found = find_device(parts[1], device);
        if (!device.key.empty()) OPENSSL_cleanse(&device.key[0], device.key.size());
        if (found == Lookup::Error) return "ERR\n";
        return found == Lookup::Found && device.status == 1 ? "ACTIVE\n" : "INACTIVE\n";
    }
    return "ERR\n";
}

// Reads one '\n'-terminated line of at most MAX_REQUEST bytes. False on EOF
// before a newline, on timeout, or on an over-long line -- all rejections.
bool read_line(int fd, std::string& out) {
    char buf[MAX_REQUEST + 1];
    size_t len = 0;
    while (len < sizeof buf) {
        ssize_t r = read(fd, buf + len, sizeof buf - len);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return false;
        for (ssize_t i = 0; i < r; i++) {
            if (buf[len + i] == '\n') {
                out.assign(buf, len + i);
                OPENSSL_cleanse(buf, sizeof buf);
                return true;
            }
        }
        len += r;
    }
    OPENSSL_cleanse(buf, sizeof buf);
    return false;
}

void write_all(int fd, const std::string& s) {
    size_t off = 0;
    while (off < s.size()) {
        ssize_t w = write(fd, s.data() + off, s.size() - off);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return;
        off += w;
    }
}

bool peer_allowed(int fd, long allow_uid) {
    if (allow_uid < 0) return true;
    uid_t uid;
#ifdef __linux__
    struct ucred cred;
    socklen_t len = sizeof cred;
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) return false;
    uid = cred.uid;
#else
    gid_t gid;
    if (getpeereid(fd, &uid, &gid) != 0) return false;
#endif
    return static_cast<long>(uid) == allow_uid;
}

void serve(int fd, long allow_uid) {
    struct timeval tv = { IO_TIMEOUT_SEC, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

    std::string line;
    if (!peer_allowed(fd, allow_uid)) {
        std::cerr << "verifier: refused a connection from a disallowed uid" << std::endl;
    } else if (read_line(fd, line)) {
        write_all(fd, handle_request(line));
    } else {
        write_all(fd, "ERR\n");
    }
    if (!line.empty()) OPENSSL_cleanse(&line[0], line.size());
    close(fd);
    in_flight--;
}

void harden_process() {
    // Core dumps would write the key and the dummy key to disk.
    struct rlimit none = { 0, 0 };
    setrlimit(RLIMIT_CORE, &none);
#ifdef __linux__
    // Also blocks ptrace from other processes running as the same uid.
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif
    // A client that disconnects mid-reply must not kill the daemon.
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, on_signal);
    signal(SIGINT, on_signal);
}

int usage() {
    std::cerr << "usage: verifier --socket PATH [--mode 0660] [--allow-uid UID]" << std::endl;
    return 2;
}

}  // namespace

int main(int argc, char** argv) {
    std::string path;
    mode_t mode = 0660;
    long allow_uid = -1;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (i + 1 >= argc) return usage();
        std::string val = argv[++i];
        try {
            if (arg == "--socket") path = val;
            else if (arg == "--mode") mode = static_cast<mode_t>(std::stoul(val, nullptr, 8));
            else if (arg == "--allow-uid") allow_uid = std::stol(val);
            else return usage();
        } catch (const std::exception&) {
            return usage();
        }
    }
    if (path.empty() || path.size() >= sizeof socket_path) return usage();
    std::strncpy(socket_path, path.c_str(), sizeof socket_path - 1);

    harden_process();
    dummy_key = random_hex_key();

    // Fail at startup, not on the first login, if the keystore is unreadable.
    Device probe;
    if (find_device("0000", probe) == Lookup::Error) {
        std::cerr << "verifier: keystore " << db_path() << " is not readable" << std::endl;
        return 1;
    }

    // Replace a stale socket from a previous run, but never delete anything
    // that is not a socket -- a typo in --socket must not remove a real file.
    struct stat st;
    if (lstat(socket_path, &st) == 0) {
        if (!S_ISSOCK(st.st_mode)) {
            std::cerr << "verifier: " << path << " exists and is not a socket" << std::endl;
            return 1;
        }
        unlink(socket_path);
    }

    int listener = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listener < 0) { perror("verifier: socket"); return 1; }
    fcntl(listener, F_SETFD, FD_CLOEXEC);

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, socket_path, sizeof addr.sun_path - 1);

    // Create the socket with no permissions for anyone outside owner+group, so
    // there is no window between bind() and chmod() where it is world-writable.
    mode_t old_umask = umask(0177);
    int rc = bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof addr);
    umask(old_umask);
    if (rc != 0) { perror("verifier: bind"); return 1; }
    if (chmod(socket_path, mode & 0770) != 0) { perror("verifier: chmod"); return 1; }
    if (listen(listener, 64) != 0) { perror("verifier: listen"); return 1; }

    std::cerr << "verifier: listening on " << path << ", keystore " << db_path() << std::endl;

    for (;;) {
        int fd = accept(listener, nullptr, nullptr);
        if (fd < 0) {
            if (errno == EINTR || errno == ECONNABORTED) continue;
            perror("verifier: accept");
            continue;
        }
        fcntl(fd, F_SETFD, FD_CLOEXEC);
        if (in_flight.fetch_add(1) >= MAX_IN_FLIGHT) {
            // Busy: refuse rather than queue unbounded threads. auth-web
            // treats this as a failed attempt, which is the safe side.
            in_flight--;
            write_all(fd, "ERR\n");
            close(fd);
            continue;
        }
        std::thread(serve, fd, allow_uid).detach();
    }
}
